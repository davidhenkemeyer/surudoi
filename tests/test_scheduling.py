from datetime import date, datetime, time

import pytest

from surudoi.scheduling import availability, parse_range, parse_time, slot_starts

from .conftest import make_store


@pytest.mark.parametrize("raw, expected", [
    ("1100", time(11, 0)), ("930", time(9, 30)), ("9", time(9, 0)), ("19:00", time(19, 0)),
    ("19:00:00", time(19, 0)), ("11am", time(11, 0)), ("7pm", time(19, 0)), ("7:30 PM", time(19, 30)),
    ("12am", time(0, 0)), ("12pm", time(12, 0)), ("2400", time(23, 59)),
    ("", None), ("closed", None), ("Closed", None),
])
def test_parse_time(raw, expected):
    assert parse_time(raw) == expected


@pytest.mark.parametrize("raw", ["25:00", "13pm", "noonish", "9:75"])
def test_parse_time_rejects_garbage(raw):
    with pytest.raises(ValueError):
        parse_time(raw)


def test_parse_range():
    assert parse_range("11am - 7pm") == (time(11), time(19))
    assert parse_range("09:00 to 17:30") == (time(9), time(17, 30))
    assert parse_range("Closed") is None


def test_slots_fit_inside_hours(app):
    store = make_store(slot_minutes=45)
    store.hours = {"mon": ["09:00", "11:00"]}
    monday = date(2026, 10, 5)
    assert slot_starts(store, monday) == [datetime(2026, 10, 5, 9, 0), datetime(2026, 10, 5, 9, 45)]
    assert slot_starts(store, date(2026, 10, 6)) == []  # Tuesday closed


def test_availability_respects_lead_time(app):
    store = make_store()
    now = datetime(2026, 10, 5, 12, 10)
    days = availability(store, days_ahead=2, min_lead_minutes=60, now=now)
    assert days[0]["slots"][0]["start"] == datetime(2026, 10, 5, 13, 30)
    assert days[1]["slots"][0]["start"] == datetime(2026, 10, 6, 9, 0)
