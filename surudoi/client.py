"""Client pages: find a store on the map, book, view/cancel/reschedule."""
from datetime import datetime

from flask import (
    Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template, request, url_for,
)

from . import geo
from .auth import login_required
from .booking import BookingError, book, cancel, open_appointment_for
from .models import STATUS_BOOKED, Appointment, Store, db
from .scheduling import availability, day_key, next_available
from .template_helpers import clock, day_label, hours_text, money

bp = Blueprint("client", __name__)


def _rules():
    return current_app.config["SITE"]["booking"]


@bp.route("/")
def home():
    appt = open_appointment_for(g.user) if g.user else None
    return render_template("client/home.html", appointment=appt, radius=_rules()["search_radius_miles"])


@bp.route("/api/stores/near")
def stores_near():
    try:
        lat, lng = float(request.args["lat"]), float(request.args["lng"])
    except (KeyError, ValueError):
        return jsonify(error="lat and lng are required"), 400
    radius = float(_rules()["search_radius_miles"])
    located = [
        (geo.distance_miles(lat, lng, s.latitude, s.longitude), s)
        for s in Store.query.filter(Store.active.is_(True), Store.latitude.isnot(None))
    ]
    located.sort(key=lambda pair: pair[0])
    nearby = [pair for pair in located if pair[0] <= radius]
    within = bool(nearby)
    if not within:
        nearby = located[:3]  # nothing in range: offer the closest few anyway
    return jsonify(
        radius_miles=radius,
        within_radius=within,
        stores=[_store_json(s, dist) for dist, s in nearby[:50]],
    )


def _store_json(store, distance):
    rules = _rules()
    nxt = next_available(store, rules["days_ahead"], rules["min_lead_minutes"])
    today = store.now_local().date()
    return {
        "id": store.id,
        "name": store.name,
        "address": store.address,
        "city_line": f"{store.city}, {store.state} {store.zip_code}".strip(", "),
        "phone": store.phone,
        "lat": store.latitude,
        "lng": store.longitude,
        "distance_miles": round(distance, 1),
        "price": money(store.price_cents),
        "today_hours": hours_text(store.hours_for(day_key(today))),
        "next_available": f"{day_label(nxt, today)}, {clock(nxt)}" if nxt else None,
        "url": url_for("client.store", store_id=store.id),
    }


@bp.route("/api/places")
def places():
    hit = geo.search_place(request.args.get("q", ""))
    if not hit:
        return jsonify(error="We couldn't find that place. Try a city and state, or a ZIP code."), 404
    return jsonify(hit)


@bp.route("/stores/<int:store_id>")
def store(store_id):
    store = db.get_or_404(Store, store_id)
    if not store.active and not (g.user and g.user.can_manage(store)):
        abort(404)
    rules = _rules()
    days = availability(store, rules["days_ahead"], rules["min_lead_minutes"])
    current = open_appointment_for(g.user) if g.user else None
    return render_template(
        "client/store.html", store=store, days=days, current=current,
        today=store.now_local().date(),
        reschedule=request.args.get("reschedule") == "1" and current is not None,
    )


@bp.route("/stores/<int:store_id>/book", methods=["POST"])
@login_required
def book_slot(store_id):
    store = db.get_or_404(Store, store_id)
    try:
        starts_at = datetime.fromisoformat(request.form.get("starts_at", ""))
    except ValueError:
        flash("Please pick a time first.", "error")
        return redirect(url_for("client.store", store_id=store.id))
    try:
        appt = book(g.user, store, starts_at, request.form.get("notes", ""),
                    replace_existing=request.form.get("replace") == "1")
    except BookingError as e:
        flash(str(e), "error")
        return redirect(url_for("client.store", store_id=store.id, reschedule=request.form.get("replace")))
    when = day_label(appt.starts_at, store.now_local().date())
    when = when.lower() if when in ("Today", "Tomorrow") else f"on {when}"
    flash(f"You're booked! See you {when} at {clock(appt.starts_at)}.", "success")
    return redirect(url_for("client.appointments"))


@bp.route("/appointments")
@login_required
def appointments():
    current = open_appointment_for(g.user)
    history = (
        Appointment.query.filter(Appointment.user_id == g.user.id, Appointment.status != STATUS_BOOKED)
        .order_by(Appointment.starts_at.desc())
        .limit(20)
        .all()
    )
    return render_template("client/appointments.html", current=current, history=history)


@bp.route("/appointments/<int:appt_id>/cancel", methods=["POST"])
@login_required
def cancel_appointment(appt_id):
    appt = db.get_or_404(Appointment, appt_id)
    if appt.user_id != g.user.id:
        abort(404)
    try:
        cancel(appt)
        flash("Your appointment was canceled. You can book a new one any time.", "success")
    except BookingError as e:
        flash(str(e), "error")
    return redirect(url_for("client.appointments"))
