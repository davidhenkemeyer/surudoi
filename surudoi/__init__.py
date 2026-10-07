"""Surudoi: a small, rebrandable appointment booking app."""
import json
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template

from .models import db

DEFAULT_SITE = {
    "brand": {
        "name": "Surudoi",
        "app_name": "Surudoi Booking",
        "tagline": "Book an appointment at a location near you.",
        "service": "Appointment",
        "logo_text": "S",
        "primary_color": "#1f5eff",
        "support_email": "",
    },
    "booking": {
        "search_radius_miles": 50,
        "days_ahead": 14,
        "min_lead_minutes": 60,
        "default_price": 0,
        "default_slot_minutes": 30,
        "default_capacity": 1,
        "notes_prompt": "Anything the store should know?",
    },
    # "none": email only for everyone; "admins": store/global admins must also
    # enter a one-time code sent to their inbox; "everyone": codes for all.
    "auth": {"email_codes_for": "admins"},
}


def load_site_config(path):
    site = json.loads(json.dumps(DEFAULT_SITE))
    if path and Path(path).is_file():
        with open(path, encoding="utf-8") as f:
            overrides = json.load(f)
        for section, values in overrides.items():
            if isinstance(values, dict):
                site.setdefault(section, {}).update(values)
            else:
                site[section] = values
    return site


def _secret_key(instance_path):
    key_file = Path(instance_path) / "secret_key"
    if key_file.is_file():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    return key


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def create_app(test_config=None):
    # A tenant is one independent business (brand, stores, users, bookings)
    # served by the same code. Each gets tenants/<name>/site.json plus its own
    # instance/<name>/ folder holding its database and secret key.
    tenant = os.environ.get("SURUDOI_TENANT", "").strip().lower()
    if tenant and not re.fullmatch(r"[a-z0-9][a-z0-9-]*", tenant):
        raise ValueError(f"SURUDOI_TENANT must be lowercase letters, digits and dashes, got {tenant!r}")
    site_config = PROJECT_ROOT / "tenants" / tenant / "site.json" if tenant else PROJECT_ROOT / "site.json"
    if tenant and not site_config.is_file():
        raise FileNotFoundError(f"No site config for tenant {tenant!r} at {site_config}")
    instance_path = str(PROJECT_ROOT / "instance" / tenant) if tenant else None
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or _secret_key(app.instance_path),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///" + os.path.join(app.instance_path, "surudoi.db")
        ),
        SITE_CONFIG=os.environ.get("SITE_CONFIG", str(site_config)),
        TENANT=tenant,
        # Distinct cookie names keep tenants' sign-ins apart when they share a
        # host (e.g. two ports on localhost, where browsers share cookies).
        SESSION_COOKIE_NAME=f"session-{tenant}" if tenant else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        GEOCODING_ENABLED=os.environ.get("GEOCODING_ENABLED", "1") == "1",
        SMTP_HOST=os.environ.get("SMTP_HOST"),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
        SMTP_USER=os.environ.get("SMTP_USER"),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD"),
        SMTP_FROM=os.environ.get("SMTP_FROM"),
    )
    if test_config:
        app.config.update(test_config)
    app.config["SITE"] = load_site_config(app.config["SITE_CONFIG"])

    db.init_app(app)

    from . import admin, auth, cli, client, manage, template_helpers

    auth.init_app(app)
    template_helpers.init_app(app)
    cli.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(client.bp)
    app.register_blueprint(manage.bp)
    app.register_blueprint(admin.bp)

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, message=e.description or "Something was wrong with that request."), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, message="You don't have access to that page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="We couldn't find that page."), 404

    with app.app_context():
        db.create_all()

    return app
