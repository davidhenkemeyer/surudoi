from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from surudoi.booking import BookingError, book, cancel, open_appointment_for
from surudoi.models import (
    STATUS_BOOKED, STATUS_CANCELED, STATUS_EXPIRED, Appointment, db,
)

from .conftest import login, make_store, make_user, post, tomorrow_at


def test_one_open_appointment_per_client(app, store):
    user = make_user()
    book(user, store, tomorrow_at(store, 10))
    with pytest.raises(BookingError, match="already have an appointment"):
        book(user, store, tomorrow_at(store, 11))


def test_database_enforces_single_open_appointment(app, store):
    user = make_user()
    db.session.add(Appointment(user=user, store=store, starts_at=tomorrow_at(store, 10), duration_minutes=30))
    db.session.commit()
    db.session.add(Appointment(user=user, store=store, starts_at=tomorrow_at(store, 11), duration_minutes=30))
    with pytest.raises(IntegrityError):
        db.session.commit()


def test_cancel_then_rebook(app, store):
    user = make_user()
    appt = book(user, store, tomorrow_at(store, 10))
    cancel(appt)
    again = book(user, store, tomorrow_at(store, 10))
    assert again.status == STATUS_BOOKED


def test_reschedule_replaces_existing(app, store):
    other = make_store("Other Store")
    user = make_user()
    first = book(user, store, tomorrow_at(store, 10))
    second = book(user, other, tomorrow_at(other, 14), replace_existing=True)
    assert first.status == STATUS_CANCELED
    assert open_appointment_for(user) == second


def test_capacity_is_enforced(app):
    store = make_store(capacity=2)
    slot = tomorrow_at(store, 10)
    book(make_user("a@example.com"), store, slot)
    book(make_user("b@example.com"), store, slot)
    with pytest.raises(BookingError, match="just taken"):
        book(make_user("c@example.com"), store, slot)


def test_rejects_times_outside_hours_or_grid(app, store):
    user = make_user()
    for bad in (tomorrow_at(store, 8), tomorrow_at(store, 17), tomorrow_at(store, 10, 10),
                store.now_local() - timedelta(hours=2), tomorrow_at(store, 10) + timedelta(days=30)):
        with pytest.raises(BookingError):
            book(user, store, bad.replace(second=0, microsecond=0))


def test_blocked_users_and_hidden_stores_cannot_book(app, store):
    user = make_user()
    user.blocked = True
    with pytest.raises(BookingError):
        book(user, store, tomorrow_at(store, 10))
    user.blocked = False
    store.active = False
    with pytest.raises(BookingError):
        book(user, store, tomorrow_at(store, 10))


def test_stale_appointment_does_not_lock_client_out(app, store):
    user = make_user()
    old = Appointment(user=user, store=store, duration_minutes=30,
                      starts_at=store.now_local().replace(microsecond=0) - timedelta(days=2))
    db.session.add(old)
    db.session.commit()
    assert open_appointment_for(user) is None
    assert old.status == STATUS_EXPIRED
    book(user, store, tomorrow_at(store, 10))


def test_booking_flow_over_http(app, client, store):
    user = make_user()
    login(client, user)
    slot = tomorrow_at(store, 10).isoformat(timespec="minutes")
    page = client.get(f"/stores/{store.id}")
    assert slot.encode() in page.data

    r = post(client, f"/stores/{store.id}/book", starts_at=slot, notes="2 pairs")
    assert r.status_code == 302 and r.location.endswith("/appointments")
    appt = Appointment.query.one()
    assert appt.notes == "2 pairs"
    assert slot.encode() not in client.get(f"/stores/{store.id}").data  # slot now full

    # A second booking without "replace" is refused.
    r = post(client, f"/stores/{store.id}/book", starts_at=tomorrow_at(store, 11).isoformat())
    assert Appointment.query.count() == 1

    r = post(client, f"/appointments/{appt.id}/cancel")
    assert db.session.get(Appointment, appt.id).status == STATUS_CANCELED


def test_cannot_cancel_someone_elses_appointment(app, client, store):
    owner, intruder = make_user("owner@example.com"), make_user("intruder@example.com")
    appt = book(owner, store, tomorrow_at(store, 10))
    login(client, intruder)
    assert post(client, f"/appointments/{appt.id}/cancel").status_code == 404
    assert appt.status == STATUS_BOOKED


def test_booking_requires_login(client, store):
    r = post(client, f"/stores/{store.id}/book", starts_at=tomorrow_at(store, 10).isoformat())
    assert r.status_code == 302 and "/login" in r.location
