"""Global admin: stores (incl. CSV import/export), users, and an overview."""
from flask import Blueprint, Response, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, or_

from .auth import normalize_email, roles_required
from .models import (
    DAYS, ROLE_ADMIN, ROLE_STORE_ADMIN, ROLES, STATUS_BOOKED, STATUS_CANCELED, STATUS_NO_SHOW, Appointment, Store, User, db,
)
from .stores import apply_store_form, decode_csv_bytes, export_stores, geocode_missing, import_stores

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@roles_required(ROLE_ADMIN)
def require_admin():
    return None


@bp.route("/")
def dashboard():
    stats = {
        "stores": Store.query.count(),
        "active_stores": Store.query.filter_by(active=True).count(),
        "unmapped": Store.query.filter(Store.latitude.is_(None)).count(),
        "users": User.query.count(),
        "staff": User.query.filter(User.role != "client").count(),
        "open_appts": Appointment.query.filter_by(status=STATUS_BOOKED).count(),
        "blocked": User.query.filter_by(blocked=True).count(),
    }
    busiest = (
        db.session.query(Store, func.count(Appointment.id).label("n"))
        .join(Appointment)
        .filter(Appointment.status == STATUS_BOOKED)
        .group_by(Store.id)
        .order_by(func.count(Appointment.id).desc())
        .limit(5)
        .all()
    )
    return render_template("admin/dashboard.html", stats=stats, busiest=busiest)


# --- Stores -----------------------------------------------------------------

@bp.route("/stores")
def stores():
    q = request.args.get("q", "").strip()
    query = Store.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Store.name.ilike(like), Store.city.ilike(like),
                                 Store.state.ilike(like), Store.zip_code.ilike(like)))
    open_counts = dict(
        db.session.query(Appointment.store_id, func.count(Appointment.id))
        .filter(Appointment.status == STATUS_BOOKED).group_by(Appointment.store_id).all()
    )
    return render_template("admin/stores.html", stores=query.order_by(Store.state, Store.city, Store.name).all(),
                           q=q, open_counts=open_counts)


@bp.route("/stores/new", methods=["GET", "POST"])
def store_new():
    rules = current_app.config["SITE"]["booking"]
    store = Store(
        hours={d: ["10:00", "18:00"] for d in DAYS[:6]}, active=True, timezone="",
        price_cents=round(float(rules["default_price"]) * 100),
        slot_minutes=int(rules["default_slot_minutes"]), capacity=int(rules["default_capacity"]),
    )
    return _store_form(store, is_new=True)


@bp.route("/stores/<int:store_id>/edit", methods=["GET", "POST"])
def store_edit(store_id):
    return _store_form(db.get_or_404(Store, store_id), is_new=False)


def _store_form(store, is_new):
    if request.method == "POST":
        errors = apply_store_form(store, request.form, full=True)
        if errors:
            db.session.rollback()
            for e in errors:
                flash(e, "error")
            return render_template("admin/store_form.html", store=store, form=request.form, is_new=is_new), 400
        if is_new:
            db.session.add(store)
        db.session.commit()
        msg = "Store added." if is_new else "Store saved."
        if store.latitude is None:
            msg += " We couldn't find it on the map — add latitude/longitude so clients can see it."
        flash(msg, "success" if store.latitude is not None else "info")
        return redirect(url_for("admin.stores"))
    return render_template("admin/store_form.html", store=store, form=None, is_new=is_new)


@bp.route("/stores/<int:store_id>/delete", methods=["POST"])
def store_delete(store_id):
    store = db.get_or_404(Store, store_id)
    for u in store.staff:
        u.store_id = None
    db.session.delete(store)
    db.session.commit()
    flash(f"Deleted {store.name} and its appointments.", "success")
    return redirect(url_for("admin.stores"))


@bp.route("/stores/import", methods=["POST"])
def store_import():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV file to import.", "error")
        return redirect(url_for("admin.stores"))
    result = import_stores(decode_csv_bytes(upload.read()), geocode=bool(request.form.get("geocode")))
    flash(f"Import finished: {result.summary}.", "success" if not result.errors else "info")
    for e in result.errors[:10]:
        flash(e, "error")
    if len(result.errors) > 10:
        flash(f"…and {len(result.errors) - 10} more problems.", "error")
    if result.not_located:
        flash("Couldn't find on the map: " + ", ".join(result.not_located[:10]) +
              (" …" if len(result.not_located) > 10 else "") + ". Add their coordinates by editing them.", "info")
    return redirect(url_for("admin.stores"))


@bp.route("/stores/export")
def store_export():
    return Response(export_stores(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=stores.csv"})


@bp.route("/stores/geocode", methods=["POST"])
def store_geocode():
    found, missing = geocode_missing()
    flash(f"Located {found} store(s) on the map.", "success")
    if missing:
        flash("Still missing coordinates: " + ", ".join(missing[:10]), "info")
    return redirect(url_for("admin.stores"))


# --- Users ------------------------------------------------------------------

@bp.route("/users")
def users():
    q = request.args.get("q", "").strip()
    role = request.args.get("role", "")
    query = User.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.email.ilike(like), User.name.ilike(like)))
    if role in ROLES:
        query = query.filter(User.role == role)
    if request.args.get("blocked"):
        query = query.filter(User.blocked.is_(True))
    users = query.order_by(User.created_at.desc()).limit(300).all()
    no_shows = dict(
        db.session.query(Appointment.user_id, func.count(Appointment.id))
        .filter(Appointment.status == STATUS_NO_SHOW).group_by(Appointment.user_id).all()
    )
    return render_template("admin/users.html", users=users, q=q, role=role, no_shows=no_shows,
                           stores=Store.query.order_by(Store.name).all())


@bp.route("/users/new", methods=["POST"])
def user_new():
    user = User()
    errors = _apply_user_form(user, request.form)
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("admin.users"))
    db.session.add(user)
    db.session.commit()
    flash(f"Added {user.email}. They can sign in with just their email.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
def user_edit(user_id):
    user = db.get_or_404(User, user_id)
    if request.method == "POST":
        errors = _apply_user_form(user, request.form)
        if user.id == g.user.id and (user.role != ROLE_ADMIN or user.blocked):
            errors.append("You can't remove your own admin access or block yourself.")
        if errors:
            db.session.rollback()
            for e in errors:
                flash(e, "error")
            return redirect(url_for("admin.user_edit", user_id=user_id))
        db.session.commit()
        flash("User saved.", "success")
        return redirect(url_for("admin.users"))
    appts = Appointment.query.filter_by(user_id=user.id).order_by(Appointment.starts_at.desc()).limit(25).all()
    return render_template("admin/user_form.html", user=user, appts=appts,
                           stores=Store.query.order_by(Store.name).all())


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
def user_delete(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == g.user.id:
        flash("You can't delete your own account.", "error")
        return redirect(url_for("admin.user_edit", user_id=user_id))
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted {user.email} and their appointments.", "success")
    return redirect(url_for("admin.users"))


def _apply_user_form(user, form):
    errors = []
    email = normalize_email(form.get("email"))
    if not email:
        errors.append("Enter a valid email address.")
    elif User.query.filter(User.email == email, User.id != (user.id or 0)).first():
        errors.append(f"{email} already has an account.")
    role = form.get("role", "client")
    if role not in ROLES:
        errors.append("Pick a role.")
    store_id = form.get("store_id", type=int)
    store = db.session.get(Store, store_id) if store_id else None
    if role == ROLE_STORE_ADMIN and store is None:
        errors.append("Store admins need a store.")
    if errors:
        return errors
    user.email = email
    user.name = form.get("name", "").strip()[:120]
    user.role = role
    user.store_id = store.id if role == ROLE_STORE_ADMIN else None
    user.blocked = bool(form.get("blocked"))
    if user.blocked and user.id:
        for appt in Appointment.query.filter_by(user_id=user.id, status=STATUS_BOOKED):
            appt.status = STATUS_CANCELED
    return []
