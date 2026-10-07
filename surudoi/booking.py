"""Booking rules: one open appointment per client, slot validation, capacity."""
from flask import current_app
from sqlalchemy.exc import IntegrityError

from .models import (
    STATUS_BOOKED, STATUS_CANCELED, STATUS_EXPIRED, Appointment, db,
)
from .scheduling import is_bookable_slot


class BookingError(Exception):
    pass


def open_appointment_for(user):
    """The client's one open appointment, or None. Quietly retires stale ones."""
    appt = Appointment.query.filter_by(user_id=user.id, status=STATUS_BOOKED).first()
    if appt and appt.is_stale():
        appt.status = STATUS_EXPIRED
        db.session.commit()
        return None
    return appt


def _active_count(store, starts_at):
    return Appointment.query.filter(
        Appointment.store_id == store.id,
        Appointment.starts_at == starts_at,
        Appointment.status != STATUS_CANCELED,
    ).count()


def book(user, store, starts_at, notes="", replace_existing=False):
    """Book `starts_at` at `store` for `user`.

    With `replace_existing`, the client's current open appointment is canceled
    in the same transaction (a reschedule); otherwise having one is an error.
    """
    rules = current_app.config["SITE"]["booking"]
    if user.blocked:
        raise BookingError("This account can't make bookings. Please contact the store.")
    if not store.active:
        raise BookingError("This location isn't taking bookings right now.")

    existing = open_appointment_for(user)
    if existing and not replace_existing:
        raise BookingError("You already have an appointment. Cancel or reschedule it before booking another.")
    if existing and existing.store_id == store.id and existing.starts_at == starts_at:
        raise BookingError("That's already your appointment time.")
    if not is_bookable_slot(store, starts_at, rules["days_ahead"], rules["min_lead_minutes"]):
        raise BookingError("That time isn't available. Please pick another.")
    if _active_count(store, starts_at) >= store.capacity:
        raise BookingError("Sorry, that time was just taken. Please pick another.")

    try:
        if existing:
            existing.status = STATUS_CANCELED
            db.session.flush()
        appt = Appointment(
            user=user, store=store, starts_at=starts_at,
            duration_minutes=store.slot_minutes, price_cents=store.price_cents,
            notes=(notes or "").strip()[:500],
        )
        db.session.add(appt)
        db.session.flush()
        # Re-check inside the transaction in case two people grabbed the last spot.
        if _active_count(store, starts_at) > store.capacity:
            raise BookingError("Sorry, that time was just taken. Please pick another.")
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise BookingError("You already have an appointment. Cancel or reschedule it before booking another.")
    except BookingError:
        db.session.rollback()
        raise
    return appt


def cancel(appt):
    if appt.status != STATUS_BOOKED:
        raise BookingError("Only upcoming appointments can be canceled.")
    appt.status = STATUS_CANCELED
    db.session.commit()


def set_status(appt, status):
    """Staff status change (complete, no-show, cancel, or back to booked)."""
    appt.status = status
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise BookingError("That client already has another open appointment, so this one can't be re-opened.")
