import re

from surudoi.booking import book
from surudoi.models import STATUS_BOOKED, STATUS_CANCELED, STATUS_COMPLETED, User, db

from .conftest import CSRF, login, make_store, make_user, post, tomorrow_at


def test_email_only_login_creates_client(client):
    r = post(client, "/login", email="  New.Person@Example.com ")
    assert r.status_code == 302
    user = User.query.one()
    assert user.email == "new.person@example.com" and user.role == "client"
    with client.session_transaction() as s:
        assert s["uid"] == user.id


def test_invalid_email_rejected(client):
    assert post(client, "/login", email="not-an-email").status_code == 400
    assert User.query.count() == 0


def test_admin_login_needs_emailed_code(client, admin, capsys):
    r = post(client, "/login", email=admin.email)
    assert r.location.endswith("/login/verify")
    with client.session_transaction() as s:
        assert "uid" not in s
    code = re.search(r"sign-in code is (\d{6})", capsys.readouterr().out).group(1)

    with client.session_transaction() as s:
        s["csrf"] = CSRF
    assert post(client, "/login/verify", code="000000" if code != "000000" else "111111").status_code == 400
    r = post(client, "/login/verify", code=code)
    assert r.status_code == 302 and r.location.endswith("/admin/")
    with client.session_transaction() as s:
        assert s["uid"] == admin.id


def test_blocked_user_cannot_sign_in(client):
    user = make_user()
    user.blocked = True
    db.session.commit()
    assert post(client, "/login", email=user.email).status_code == 403


def test_post_without_csrf_token_is_rejected(client):
    assert client.post("/login", data={"email": "a@example.com"}).status_code == 400


def test_open_redirect_blocked(client):
    r = post(client, "/login", email="a@example.com", next="https://evil.example/")
    assert r.location == "/"


def test_clients_cannot_reach_staff_pages(client):
    login(client, make_user())
    assert client.get("/manage/").status_code == 403
    assert client.get("/admin/").status_code == 403


def test_store_admin_manages_only_their_store(client, store, store_admin):
    other = make_store("Elsewhere")
    mine = book(make_user("a@example.com"), store, tomorrow_at(store, 10))
    theirs = book(make_user("b@example.com"), other, tomorrow_at(other, 10))
    login(client, store_admin)

    page = client.get(f"/manage/?date={mine.starts_at.date().isoformat()}&store={other.id}")
    assert b"a@example.com" in page.data and b"b@example.com" not in page.data

    post(client, f"/manage/appointments/{mine.id}/status", status="completed")
    assert mine.status == STATUS_COMPLETED
    assert post(client, f"/manage/appointments/{theirs.id}/status", status="completed").status_code == 403
    assert theirs.status == STATUS_BOOKED
    assert client.get("/admin/").status_code == 403


def test_store_admin_can_edit_hours(client, store, store_admin):
    login(client, store_admin)
    form = {"price": "12.50", "slot_minutes": "20", "capacity": "3", "active": "1",
            "open_mon": "1", "mon_open": "08:00", "mon_close": "12:00"}
    r = post(client, "/manage/settings", **form)
    assert r.status_code == 302
    assert store.price_cents == 1250 and store.capacity == 3
    assert store.hours == {"mon": ["08:00", "12:00"]}


def test_admin_blocking_cancels_open_appointment(client, admin, store):
    target = make_user("griefer@example.com")
    appt = book(target, store, tomorrow_at(store, 10))
    login(client, admin)
    post(client, f"/admin/users/{target.id}/edit", email=target.email, role="client", blocked="1")
    assert target.blocked and appt.status == STATUS_CANCELED


def test_admin_creates_store_admin(client, admin, store):
    login(client, admin)
    post(client, "/admin/users/new", email="boss@example.com", role="store_admin", store_id=str(store.id))
    assert User.query.filter_by(email="boss@example.com").one().store_id == store.id
    # A store admin without a store is refused.
    post(client, "/admin/users/new", email="nostore@example.com", role="store_admin")
    assert User.query.filter_by(email="nostore@example.com").first() is None


def test_admin_cannot_demote_self(client, admin):
    login(client, admin)
    post(client, f"/admin/users/{admin.id}/edit", email=admin.email, role="client")
    db.session.refresh(admin)
    assert admin.role == "admin"
