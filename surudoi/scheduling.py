"""Opening hours parsing and appointment slot generation."""
import re
from datetime import date, datetime, time, timedelta

from sqlalchemy import func

from .models import DAYS, Appointment, STATUS_CANCELED, db

_TIME_RE = re.compile(r"(\d{1,2})(?::?(\d{2}))?(?::\d{2})?\s*(?:([ap])\.?\s*m?\.?)?")
_CLOSED = {"", "closed", "-", "n/a", "na", "none", "x"}


def parse_time(value):
    """Parse '1100', '11:00', '11:00:00', '11am', '7:30 pm' -> time. Blank/closed -> None."""
    s = str(value if value is not None else "").strip().lower()
    if s in _CLOSED:
        return None
    m = _TIME_RE.fullmatch(s)
    if not m:
        raise ValueError(f"Can't read time {value!r}")
    hour, minute, ampm = int(m.group(1)), int(m.group(2) or 0), m.group(3)
    if ampm:
        if not 1 <= hour <= 12:
            raise ValueError(f"Can't read time {value!r}")
        hour = hour % 12 + (12 if ampm == "p" else 0)
    if hour == 24 and minute == 0:
        return time(23, 59)
    if hour > 23 or minute > 59:
        raise ValueError(f"Can't read time {value!r}")
    return time(hour, minute)


def parse_range(value):
    """Parse '11am - 7pm' / '11:00-19:00' -> (open, close). Blank/closed -> None."""
    s = str(value or "").strip().lower()
    if s in _CLOSED:
        return None
    parts = re.split(r"\s*(?:-|–|—|\bto\b)\s*", s)
    if len(parts) != 2:
        raise ValueError(f"Can't read hours {value!r}")
    return parse_time(parts[0]), parse_time(parts[1])


def hours_entry(open_t, close_t):
    """Validate an open/close pair and return the stored form (or None for closed)."""
    if open_t is None and close_t is None:
        return None
    if open_t is None or close_t is None:
        raise ValueError("Both an opening and closing time are needed")
    if close_t <= open_t:
        raise ValueError("Closing time must be after opening time")
    return [open_t.strftime("%H:%M"), close_t.strftime("%H:%M")]


def day_key(d):
    return DAYS[d.weekday()]


def slot_starts(store, d):
    span = store.hours_for(day_key(d))
    if not span:
        return []
    step = timedelta(minutes=max(store.slot_minutes, 5))
    start, end = datetime.combine(d, span[0]), datetime.combine(d, span[1])
    slots = []
    while start + step <= end:
        slots.append(start)
        start += step
    return slots


def booked_counts(store, start, end):
    rows = (
        db.session.query(Appointment.starts_at, func.count(Appointment.id))
        .filter(
            Appointment.store_id == store.id,
            Appointment.status != STATUS_CANCELED,
            Appointment.starts_at >= start,
            Appointment.starts_at < end,
        )
        .group_by(Appointment.starts_at)
        .all()
    )
    return dict(rows)


def availability(store, days_ahead, min_lead_minutes, now=None):
    """[{date, hours, slots: [{start, remaining}]}] for the booking window."""
    now = now or store.now_local()
    earliest = now + timedelta(minutes=min_lead_minutes)
    today = now.date()
    end = datetime.combine(today + timedelta(days=days_ahead), time())
    counts = booked_counts(store, datetime.combine(today, time()), end)
    days = []
    for i in range(days_ahead):
        d = today + timedelta(days=i)
        slots, upcoming = [], 0
        for start in slot_starts(store, d):
            if start < earliest:
                continue
            upcoming += 1
            remaining = store.capacity - counts.get(start, 0)
            if remaining > 0:
                slots.append({"start": start, "remaining": remaining})
        hours = store.hours_for(day_key(d))
        status = "closed" if not hours else "open" if slots else "full" if upcoming else "past"
        days.append({"date": d, "hours": hours, "slots": slots, "status": status})
    return days


def next_available(store, days_ahead, min_lead_minutes):
    for day in availability(store, days_ahead, min_lead_minutes):
        if day["slots"]:
            return day["slots"][0]["start"]
    return None


def is_bookable_slot(store, start, days_ahead, min_lead_minutes):
    now = store.now_local()
    if start < now + timedelta(minutes=min_lead_minutes):
        return False
    if start.date() >= now.date() + timedelta(days=days_ahead):
        return False
    return start in slot_starts(store, start.date())
