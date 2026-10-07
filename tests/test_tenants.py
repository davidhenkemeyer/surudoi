import pytest

from surudoi import create_app
from surudoi.models import Store, User, db
from surudoi.stores import import_stores

from .conftest import CSRF, post


def _app(monkeypatch, tmp_path, tenant, secret):
    monkeypatch.setenv("SURUDOI_TENANT", tenant)
    return create_app({
        "TESTING": True,
        "SECRET_KEY": secret,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / (tenant or 'default')}.db",
        "GEOCODING_ENABLED": False,
    })


def test_tenant_uses_its_own_branding_and_cookie(monkeypatch, tmp_path):
    acme = _app(monkeypatch, tmp_path, "acme-manicure", "a")
    assert acme.config["SITE"]["brand"]["name"] == "Acme Manicure"
    assert acme.config["SESSION_COOKIE_NAME"] == "session-acme-manicure"
    assert acme.instance_path.replace("\\", "/").endswith("instance/acme-manicure")


def test_unknown_or_bad_tenant_names_fail_loudly(monkeypatch, tmp_path):
    with pytest.raises(FileNotFoundError):
        _app(monkeypatch, tmp_path, "no-such-tenant", "x")
    with pytest.raises(ValueError):
        _app(monkeypatch, tmp_path, "../etc", "x")


def test_tenants_do_not_share_data_or_sign_ins(monkeypatch, tmp_path):
    default = _app(monkeypatch, tmp_path, "", "secret-one")
    acme = _app(monkeypatch, tmp_path, "acme-manicure", "secret-two")

    with acme.app_context():
        with open("tenants/acme-manicure/stores.csv", encoding="utf-8") as f:
            assert import_stores(f.read(), geocode=False).created == 3
    with default.app_context():
        assert Store.query.count() == 0

    # Same email signs up in both: two unrelated accounts.
    clients = {}
    for name, app in (("default", default), ("acme", acme)):
        c = app.test_client()
        with c.session_transaction() as s:
            s["csrf"] = CSRF
        post(c, "/login", email="pat@example.com")
        clients[name] = c
        with app.app_context():
            assert User.query.count() == 1

    # A browser holding only Acme's sign-in cookie is signed out of the other tenant.
    acme_cookie = clients["acme"].get_cookie("session-acme-manicure")
    stranger = default.test_client()
    stranger.set_cookie("session-acme-manicure", acme_cookie.value)
    assert b"pat@example.com" not in stranger.get("/").data
    assert stranger.get("/appointments").status_code == 302
