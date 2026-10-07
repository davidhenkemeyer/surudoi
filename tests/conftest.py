from datetime import datetime, time, timedelta

import pytest

from surudoi import create_app
from surudoi.models import DAYS, ROLE_ADMIN, ROLE_STORE_ADMIN, Store, User, db

CSRF = "test-csrf-token"


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "SITE_CONFIG": "",
        "GEOCODING_ENABLED": False,
    })
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["csrf"] = CSRF
    return c


def make_store(name="Test Store", lat=47.6, lng=-122.3, capacity=1, slot_minutes=30, **kw):
    store = Store(
        name=name, address="1 Main St", city="Seattle", state="WA", zip_code="98101",
        latitude=lat, longitude=lng, timezone="America/Los_Angeles",
        price_cents=1000, slot_minutes=slot_minutes, capacity=capacity,
        hours={d: ["09:00", "17:00"] for d in DAYS}, **kw,
    )
    db.session.add(store)
    db.session.commit()
    return store


def make_user(email="client@example.com", role="client", store=None):
    user = User(email=email, role=role, store_id=store.id if store else None)
    db.session.add(user)
    db.session.commit()
    return user


def tomorrow_at(store, hour, minute=0):
    return datetime.combine(store.now_local().date() + timedelta(days=1), time(hour, minute))


def login(client, user):
    with client.session_transaction() as s:
        s["uid"] = user.id
        s["csrf"] = CSRF


def post(client, url, **data):
    data.setdefault("csrf_token", CSRF)
    return client.post(url, data=data)


@pytest.fixture
def store(app):
    return make_store()


@pytest.fixture
def admin(app):
    return make_user("admin@example.com", ROLE_ADMIN)


@pytest.fixture
def store_admin(app, store):
    return make_user("manager@example.com", ROLE_STORE_ADMIN, store)
