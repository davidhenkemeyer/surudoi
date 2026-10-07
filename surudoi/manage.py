"""Store admin pages: the day's appointment list and store settings."""
from datetime import date, timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func

from .auth import roles_required
from .booking import BookingError, set_status
from .models import (
    ROLE_ADMIN, ROLE_STORE_ADMIN, STATUS_BOOKED, STATUS_CANCELED, STATUS_COMPLETED, STATUS_EXPIRED,
    STATUS_NO_SHOW, Appointment, Store, db,
)
from .stores import apply_store_form

bp = Blueprint("manage", __name__, url_prefix="/manage")

STAFF_STATUSES = (STATUS_BOOKED, STATUS_COMPLETED, STATUS_NO_SHOW, STATUS_CANCELED)


def _store_for_request():
    """The store being managed: a store admin's own; for global admins, the chosen one."""
    if g.user.role == ROLE_STORE_ADMIN:
        return g.user.store
    store_id = request.args.get("store", type=int) or session.get("manage_store")
    store = db.session.get(Store, store_id) if store_id else None
    store = store or Store.query.order_by(Store.name).first()
    if store:
        session["manage_store"] = store.id
    return store


@bp.route("/")
@roles_required(ROLE_ADMIN, ROLE_STORE_ADMIN)
def day():
    store = _store_for_request()
    if store is None:
        return render_template("manage/no_store.html")
    today = store.now_local().date()
    try:
        selected = date.fromisoformat(request.args.get("date", ""))
    except ValueError:
        selected = today

    appts = (
        Appointment.query.filter(
            Appointment.store_id == store.id,
            func.date(Appointment.starts_at) == selected.isoformat(),
        )
        .order_by(Appointment.starts_at, Appointment.id)
        .all()
    )
    for a in appts:
        if a.is_stale():
            a.status = STATUS_EXPIRED
    db.session.commit()

    no_shows = dict(
        db.session.query(Appointment.user_id, func.count(Appointment.id))
        .filter(Appointment.user_id.in_({a.user_id for a in appts}), Appointment.status == STATUS_NO_SHOW)
        .group_by(Appointment.user_id)
        .all()
    )
    week = [today + timedelta(days=i) for i in range(7)]
    upcoming = dict(
        db.session.query(func.date(Appointment.starts_at), func.count(Appointment.id))
        .filter(
            Appointment.store_id == store.id,
            Appointment.status == STATUS_BOOKED,
            func.date(Appointment.starts_at) >= week[0].isoformat(),
            func.date(Appointment.starts_at) <= week[-1].isoformat(),
        )
        .group_by(func.date(Appointment.starts_at))
        .all()
    )
    counts = {s: sum(1 for a in appts if a.status == s) for s in STAFF_STATUSES + (STATUS_EXPIRED,)}
    return render_template(
        "manage/day.html", store=store, appts=appts, selected=selected, today=today,
        prev_day=selected - timedelta(days=1), next_day=selected + timedelta(days=1),
        week=[(d, upcoming.get(d.isoformat(), 0)) for d in week],
        counts=counts, no_shows=no_shows,
        all_stores=Store.query.order_by(Store.name).all() if g.user.is_admin else [],
    )


@bp.route("/appointments/<int:appt_id>/status", methods=["POST"])
@roles_required(ROLE_ADMIN, ROLE_STORE_ADMIN)
def update_status(appt_id):
    appt = db.get_or_404(Appointment, appt_id)
    if not g.user.can_manage(appt.store):
        abort(403)
    status = request.form.get("status")
    if status not in STAFF_STATUSES:
        abort(400)
    try:
        set_status(appt, status)
    except BookingError as e:
        flash(str(e), "error")
    return redirect(url_for("manage.day", store=appt.store_id, date=appt.starts_at.date().isoformat()) + f"#appt-{appt.id}")


@bp.route("/settings", methods=["GET", "POST"])
@roles_required(ROLE_ADMIN, ROLE_STORE_ADMIN)
def settings():
    store = _store_for_request()
    if store is None:
        return render_template("manage/no_store.html")
    if request.method == "POST":
        errors = apply_store_form(store, request.form, full=False)
        if errors:
            db.session.rollback()
            for e in errors:
                flash(e, "error")
            return render_template("manage/settings.html", store=store, form=request.form), 400
        db.session.commit()
        flash("Store settings saved.", "success")
        return redirect(url_for("manage.settings", store=store.id))
    return render_template("manage/settings.html", store=store, form=None)
