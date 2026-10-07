"""Store CSV import/export and the shared store-editing form logic."""
import csv
import io
import re
from dataclasses import dataclass, field

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import current_app

from . import geo
from .models import DAY_NAMES, DAYS, Store, db
from .scheduling import hours_entry, parse_range, parse_time

# Normalized header -> Store field. Headers are matched ignoring case, spaces
# and punctuation, so "Zip Code", "zip_code" and "ZIPCODE" all work.
FIELD_ALIASES = {
    "name": ("name", "location", "store", "storename", "locationname"),
    "address": ("address", "street", "streetaddress", "address1"),
    "city": ("city", "town"),
    "state": ("state", "province", "region"),
    "zip_code": ("zip", "zipcode", "postal", "postalcode", "postcode"),
    "phone": ("phone", "phonenumber", "telephone"),
    "email": ("email", "emailaddress"),
    "latitude": ("latitude", "lat"),
    "longitude": ("longitude", "lng", "lon", "long"),
    "timezone": ("timezone", "tz", "timezonename"),
    "price": ("price", "cost", "priceusd", "fee"),
    "slot_minutes": ("slotminutes", "duration", "durationminutes", "minutes", "appointmentminutes"),
    "capacity": ("capacity", "slotcapacity", "perslot", "chairs"),
    "active": ("active", "enabled", "bookable"),
    "notes": ("notes", "description", "instructions"),
}
DAY_ALIASES = {
    "mon": ("monday", "mon"), "tue": ("tuesday", "tue", "tues"), "wed": ("wednesday", "wed"),
    "thu": ("thursday", "thu", "thur", "thurs"), "fri": ("friday", "fri"),
    "sat": ("saturday", "sat"), "sun": ("sunday", "sun"),
}

EXPORT_COLUMNS = [
    "Name", "Address", "City", "State", "Zip", "Phone", "Email", "Latitude", "Longitude",
    "Timezone", "Price", "SlotMinutes", "Capacity", "Active", "Notes",
] + [f"{DAY_NAMES[d]}{part}" for d in DAYS for part in ("Open", "Close")]


def _norm(header):
    return re.sub(r"[^a-z0-9]", "", (header or "").lower())


def _parse_bool(value):
    s = str(value).strip().lower()
    if s in ("1", "y", "yes", "true", "t", "active", "on"):
        return True
    if s in ("0", "n", "no", "false", "f", "inactive", "off"):
        return False
    raise ValueError(f"Expected yes/no, got {value!r}")


def parse_price_cents(value):
    s = str(value).strip().replace("$", "").replace(",", "")
    if s.lower() in ("free", ""):
        return 0
    cents = round(float(s) * 100)
    if cents < 0:
        raise ValueError("Price can't be negative")
    return cents


def _positive_int(value, label, maximum):
    n = int(str(value).strip())
    if not 1 <= n <= maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}")
    return n


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    geocoded: int = 0
    errors: list = field(default_factory=list)
    not_located: list = field(default_factory=list)

    @property
    def summary(self):
        parts = [f"{self.created} added", f"{self.updated} updated"]
        if self.geocoded:
            parts.append(f"{self.geocoded} located on the map")
        return ", ".join(parts)


def _column_map(headers):
    """Map Store fields / hour slots to the CSV header that supplies them."""
    by_norm = {_norm(h): h for h in headers if h}
    cols = {}
    for fld, aliases in FIELD_ALIASES.items():
        for a in aliases:
            if a in by_norm:
                cols[fld] = by_norm[a]
                break
    for day, aliases in DAY_ALIASES.items():
        for a in aliases:
            if f"{a}open" in by_norm and f"{a}close" in by_norm:
                cols[f"{day}_open"] = by_norm[f"{a}open"]
                cols[f"{day}_close"] = by_norm[f"{a}close"]
                break
        else:
            # Fallback: a single "Monday" column holding "11am - 7pm" or "Closed".
            for a in aliases:
                if a in by_norm:
                    cols[f"{day}_range"] = by_norm[a]
                    break
    return cols


def decode_csv_bytes(data):
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _row_changes(store, cell, cols, has_hours):
    """Work out the field changes one CSV row makes to `store` (None for a new store).

    Raises ValueError for unreadable values, so a bad row changes nothing.
    """
    is_new = store is None
    changes = {}
    for fld in ("address", "city", "state", "zip_code", "phone", "email", "notes"):
        if cell(fld) or (fld in cols and is_new):
            changes[fld] = cell(fld)
    if len(changes.get("state", "")) == 2:
        changes["state"] = changes["state"].upper()
    if cell("price"):
        changes["price_cents"] = parse_price_cents(cell("price"))
    if cell("slot_minutes"):
        changes["slot_minutes"] = _positive_int(cell("slot_minutes"), "SlotMinutes", 480)
    if cell("capacity"):
        changes["capacity"] = _positive_int(cell("capacity"), "Capacity", 100)
    if cell("active"):
        changes["active"] = _parse_bool(cell("active"))

    def current(fld):
        return changes.get(fld, "" if is_new else getattr(store, fld))

    address = tuple(current(f) for f in ("address", "city", "state", "zip_code"))
    address_changed = is_new or address != (store.address, store.city, store.state, store.zip_code)
    if cell("timezone"):
        _validate_timezone(cell("timezone"))
        changes["timezone"] = cell("timezone")
    elif is_new or current("state") != store.state:
        changes["timezone"] = geo.timezone_for_state(current("state"))
    if cell("latitude") and cell("longitude"):
        changes["latitude"], changes["longitude"] = float(cell("latitude")), float(cell("longitude"))
    elif address_changed:
        changes["latitude"] = changes["longitude"] = None  # re-geocoded after import

    if has_hours:
        hours = {}
        for d in DAYS:
            if f"{d}_open" in cols:
                entry = hours_entry(parse_time(cell(f"{d}_open")), parse_time(cell(f"{d}_close")))
            elif f"{d}_range" in cols:
                span = parse_range(cell(f"{d}_range"))
                entry = hours_entry(*span) if span else None
            else:
                entry = None if is_new else (store.hours or {}).get(d)
            if entry:
                hours[d] = entry
        changes["hours"] = hours
    return changes


def _validate_timezone(name):
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"Unknown time zone {name!r} (use names like America/Denver)") from None


def import_stores(text, geocode=True):
    """Create or update stores (matched by name) from CSV text."""
    result = ImportResult()
    reader = csv.DictReader(io.StringIO(text))
    cols = _column_map(reader.fieldnames or [])
    if "name" not in cols:
        result.errors.append("The CSV needs a store name column (e.g. 'Name' or 'Location').")
        return result
    has_hours = any(f"{d}_open" in cols or f"{d}_range" in cols for d in DAYS)
    site = current_app.config["SITE"]["booking"]
    existing = {s.name.lower(): s for s in Store.query.all()}

    for line_no, row in enumerate(reader, start=2):
        def cell(key):
            col = cols.get(key)
            return (row.get(col) or "").strip() if col else ""

        name = cell("name")
        if not name:
            if any((v or "").strip() for v in row.values() if isinstance(v, str)):
                result.errors.append(f"Row {line_no}: missing store name, skipped.")
            continue
        store = existing.get(name.lower())
        is_new = store is None
        try:
            changes = _row_changes(store, cell, cols, has_hours)
        except (ValueError, KeyError) as e:
            result.errors.append(f"Row {line_no} ({name}): {e}")
            continue
        if is_new and not changes.get("address"):
            result.errors.append(f"Row {line_no} ({name}): missing address, skipped.")
            continue
        if is_new:
            store = Store(
                name=name,
                price_cents=round(float(site["default_price"]) * 100),
                slot_minutes=int(site["default_slot_minutes"]),
                capacity=int(site["default_capacity"]),
                hours={},
            )
            db.session.add(store)
            existing[name.lower()] = store
            result.created += 1
        else:
            result.updated += 1
        for k, v in changes.items():
            setattr(store, k, v)

    db.session.commit()
    if geocode:
        located, missing = geocode_missing()
        result.geocoded = located
        result.not_located = missing
    return result


def geocode_missing():
    """Look up coordinates for stores that have none. Returns (found, [names not found])."""
    found, missing = 0, []
    for store in Store.query.filter(Store.latitude.is_(None)).order_by(Store.name):
        coords = geo.geocode_address(store.address, store.city, store.state, store.zip_code)
        if coords:
            store.latitude, store.longitude = coords
            found += 1
            db.session.commit()
        else:
            missing.append(store.name)
    return found, missing


def export_stores():
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_COLUMNS)
    for s in Store.query.order_by(Store.name):
        row = [
            s.name, s.address, s.city, s.state, s.zip_code, s.phone, s.email,
            "" if s.latitude is None else s.latitude, "" if s.longitude is None else s.longitude,
            s.timezone, f"{s.price_cents / 100:.2f}", s.slot_minutes, s.capacity,
            "yes" if s.active else "no", s.notes,
        ]
        for d in DAYS:
            span = (s.hours or {}).get(d)
            row += span if span else ["closed", "closed"]
        writer.writerow(row)
    return buf.getvalue()


def apply_store_form(store, form, full):
    """Update a store from a submitted form. `full` also allows identity/location fields.

    Returns a list of error messages; the store is only modified if there are none.
    """
    errors, values = [], {}
    if full:
        values["name"] = form.get("name", "").strip()
        if not values["name"]:
            errors.append("Store name is required.")
        elif Store.query.filter(db.func.lower(Store.name) == values["name"].lower(), Store.id != store.id).first():
            errors.append("Another store already has that name.")
        for fld in ("address", "city", "state", "zip_code", "phone", "email"):
            values[fld] = form.get(fld, "").strip()
        if not values["address"]:
            errors.append("Street address is required.")
        tz = form.get("timezone", "").strip() or geo.timezone_for_state(values["state"])
        try:
            _validate_timezone(tz)
            values["timezone"] = tz
        except ValueError as e:
            errors.append(f"{e}.")
        lat, lng = form.get("latitude", "").strip(), form.get("longitude", "").strip()
        if lat or lng:
            try:
                values["latitude"], values["longitude"] = float(lat), float(lng)
                if not (-90 <= values["latitude"] <= 90 and -180 <= values["longitude"] <= 180):
                    raise ValueError
            except ValueError:
                errors.append("Latitude/longitude must both be valid numbers (or both blank).")
        else:
            values["latitude"] = values["longitude"] = None
    try:
        values["price_cents"] = parse_price_cents(form.get("price", "0"))
    except ValueError:
        errors.append("Price must be a number like 10 or 12.50.")
    try:
        values["slot_minutes"] = _positive_int(form.get("slot_minutes", ""), "Appointment length", 480)
    except ValueError as e:
        errors.append(str(e) if "between" in str(e) else "Appointment length must be a whole number of minutes.")
    try:
        values["capacity"] = _positive_int(form.get("capacity", ""), "Bookings per time slot", 100)
    except ValueError as e:
        errors.append(str(e) if "between" in str(e) else "Bookings per time slot must be a whole number.")
    hours = {}
    for d in DAYS:
        if not form.get(f"open_{d}"):
            continue
        try:
            entry = hours_entry(parse_time(form.get(f"{d}_open")), parse_time(form.get(f"{d}_close")))
            if entry:
                hours[d] = entry
        except ValueError as e:
            errors.append(f"{DAY_NAMES[d]}: {e}.")
    values["hours"] = hours
    values["notes"] = form.get("notes", "").strip()[:1000]
    values["active"] = bool(form.get("active"))

    if errors:
        return errors
    if full:
        address_changed = (store.address, store.city, store.state, store.zip_code) != (
            values["address"], values["city"], values["state"], values["zip_code"])
        coords_untouched = (values["latitude"], values["longitude"]) == (store.latitude, store.longitude)
        if address_changed and coords_untouched:
            values["latitude"] = values["longitude"] = None
    for k, v in values.items():
        setattr(store, k, v)
    if full and store.latitude is None:
        coords = geo.geocode_address(store.address, store.city, store.state, store.zip_code)
        if coords:
            store.latitude, store.longitude = coords
    return []
