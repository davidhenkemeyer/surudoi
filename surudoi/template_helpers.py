from datetime import date, datetime, timedelta

from flask import current_app

from .models import DAY_NAMES, DAYS, ROLES, STATUSES


def money(cents):
    if not cents:
        return "Free"
    return f"${cents / 100:,.2f}".replace(".00", "")


def clock(value):
    """time/datetime -> '3:30 PM' (or '3 PM' on the hour)."""
    if value is None:
        return ""
    fmt = "%I %p" if value.minute == 0 else "%I:%M %p"
    return value.strftime(fmt).lstrip("0")


def day_label(d, today=None):
    if isinstance(d, datetime):
        d = d.date()
    today = today or date.today()
    if d == today:
        return "Today"
    if d == today + timedelta(days=1):
        return "Tomorrow"
    return f"{d.strftime('%a, %b')} {d.day}"


def long_date(d):
    if isinstance(d, datetime):
        d = d.date()
    return f"{d.strftime('%A, %B')} {d.day}"


def hours_text(span):
    if not span:
        return "Closed"
    return f"{clock(span[0])} – {clock(span[1])}"


def init_app(app):
    app.add_template_filter(money)
    app.add_template_filter(clock)
    app.add_template_filter(day_label)
    app.add_template_filter(long_date)
    app.add_template_filter(hours_text)

    @app.context_processor
    def inject_site():
        return {
            "site": current_app.config["SITE"],
            "DAYS": DAYS,
            "DAY_NAMES": DAY_NAMES,
            "ROLES": ROLES,
            "STATUSES": STATUSES,
        }
