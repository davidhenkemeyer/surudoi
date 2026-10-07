"""Email-only sign-in, optional one-time codes, roles, and CSRF protection."""
import re
import secrets
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .mailer import email_configured, send_email
from .models import ROLE_ADMIN, ROLE_CLIENT, ROLE_STORE_ADMIN, User, db, utcnow

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_TTL = timedelta(minutes=10)
MAX_CODE_ATTEMPTS = 5


def normalize_email(value):
    email = (value or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        return None
    return email


def init_app(app):
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        uid = session.get("uid")
        if uid:
            user = db.session.get(User, uid)
            if user and not user.blocked:
                g.user = user
            else:
                session.pop("uid", None)
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not token or not secrets.compare_digest(token, session.get("csrf", "")):
                abort(400, "Your session expired. Please go back, refresh the page and try again.")

    @app.context_processor
    def inject():
        return {"current_user": g.get("user"), "csrf_token": csrf_token}


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
            if g.user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _safe_next(target):
    if target and urlparse(target).netloc == "" and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def _needs_code(user):
    mode = current_app.config["SITE"]["auth"].get("email_codes_for", "admins")
    return mode == "everyone" or (mode == "admins" and user.role in (ROLE_ADMIN, ROLE_STORE_ADMIN))


def _finish_login(user):
    session.clear()
    session.permanent = True
    session["uid"] = user.id
    user.last_login_at = utcnow()
    user.login_code_hash = None
    user.login_code_attempts = 0
    db.session.commit()


def _home_for(user):
    if user.role == ROLE_ADMIN:
        return url_for("admin.dashboard")
    if user.role == ROLE_STORE_ADMIN:
        return url_for("manage.day")
    return url_for("client.home")


@bp.route("/login", methods=["GET", "POST"])
def login():
    next_url = _safe_next(request.values.get("next"))
    if g.user:
        return redirect(next_url or _home_for(g.user))
    if request.method == "GET":
        return render_template("auth/login.html", next=next_url)

    email = normalize_email(request.form.get("email"))
    if not email:
        flash("Please enter a valid email address.", "error")
        return render_template("auth/login.html", next=next_url, email=request.form.get("email", "")), 400

    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(email=email, role=ROLE_CLIENT)
        db.session.add(user)
        db.session.commit()
    if user.blocked:
        flash("This account has been disabled. Please contact the store if you think this is a mistake.", "error")
        return render_template("auth/login.html", next=next_url, email=email), 403

    if not _needs_code(user):
        _finish_login(user)
        return redirect(next_url or _home_for(user))

    code = f"{secrets.randbelow(10**6):06d}"
    user.login_code_hash = generate_password_hash(code)
    user.login_code_expires = utcnow() + CODE_TTL
    user.login_code_attempts = 0
    db.session.commit()
    brand = current_app.config["SITE"]["brand"]
    sent = send_email(
        user.email,
        f"Your {brand['app_name']} sign-in code: {code}",
        f"Your sign-in code is {code}\n\nIt expires in 10 minutes. If you didn't try to sign in, you can ignore this email.",
    )
    session["pending_uid"] = user.id
    session["pending_next"] = next_url
    if not sent and current_app.debug:
        flash(f"Email isn't set up yet, so here's your code (dev mode only): {code}", "info")
    elif not sent and not email_configured():
        flash("Email isn't set up on this server. Ask an administrator for your code (it's in the server log).", "info")
    return redirect(url_for("auth.verify"))


@bp.route("/login/verify", methods=["GET", "POST"])
def verify():
    user = db.session.get(User, session.get("pending_uid") or 0)
    if user is None:
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        return render_template("auth/verify.html", email=user.email)

    code = re.sub(r"\D", "", request.form.get("code", ""))
    if not user.login_code_hash or user.login_code_expires < utcnow() or user.login_code_attempts >= MAX_CODE_ATTEMPTS:
        flash("That code has expired. Please sign in again to get a new one.", "error")
        return redirect(url_for("auth.login"))
    if not check_password_hash(user.login_code_hash, code):
        user.login_code_attempts += 1
        db.session.commit()
        flash("That code isn't right. Check the email and try again.", "error")
        return render_template("auth/verify.html", email=user.email), 400

    next_url = session.get("pending_next")
    _finish_login(user)
    return redirect(next_url or _home_for(user))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("client.home"))
