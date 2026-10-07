from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, text

db = SQLAlchemy()

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_NAMES = {
    "mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday",
    "fri": "Friday", "sat": "Saturday", "sun": "Sunday",
}

ROLE_CLIENT = "client"
ROLE_STORE_ADMIN = "store_admin"
ROLE_ADMIN = "admin"
ROLES = {ROLE_CLIENT: "Client", ROLE_STORE_ADMIN: "Store admin", ROLE_ADMIN: "Global admin"}

STATUS_BOOKED = "booked"
STATUS_COMPLETED = "completed"
STATUS_CANCELED = "canceled"
STATUS_NO_SHOW = "no_show"
STATUS_EXPIRED = "expired"
STATUSES = {
    STATUS_BOOKED: "Booked",
    STATUS_COMPLETED: "Completed",
    STATUS_CANCELED: "Canceled",
    STATUS_NO_SHOW: "No-show",
    STATUS_EXPIRED: "Not closed out",
}

# A booked appointment this long past its end time no longer counts as the
# client's open appointment, so a store forgetting to close it out never
# locks the client out of booking again.
STALE_AFTER = timedelta(hours=3)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    address = db.Column(db.String(200), nullable=False, default="")
    city = db.Column(db.String(80), nullable=False, default="")
    state = db.Column(db.String(40), nullable=False, default="")
    zip_code = db.Column(db.String(20), nullable=False, default="")
    phone = db.Column(db.String(40), nullable=False, default="")
    email = db.Column(db.String(254), nullable=False, default="")
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timezone = db.Column(db.String(64), nullable=False, default="America/New_York")
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    slot_minutes = db.Column(db.Integer, nullable=False, default=30)
    capacity = db.Column(db.Integer, nullable=False, default=1)
    # {"mon": ["11:00", "19:00"], ...}; a missing day means closed.
    hours = db.Column(db.JSON, nullable=False, default=dict)
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    appointments = db.relationship("Appointment", back_populates="store", cascade="all, delete-orphan")
    staff = db.relationship("User", back_populates="store")

    @property
    def full_address(self):
        city_line = " ".join(p for p in (f"{self.city}," if self.city else "", self.state, self.zip_code) if p)
        return ", ".join(p for p in (self.address, city_line) if p)

    @property
    def has_location(self):
        return self.latitude is not None and self.longitude is not None

    @property
    def tz(self):
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            return ZoneInfo("America/New_York")

    def now_local(self):
        """Current wall-clock time at the store, as a naive datetime."""
        return datetime.now(self.tz).replace(tzinfo=None)

    def hours_for(self, day_key):
        span = (self.hours or {}).get(day_key)
        if not span:
            return None
        return time.fromisoformat(span[0]), time.fromisoformat(span[1])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, unique=True)
    name = db.Column(db.String(120), nullable=False, default="")
    role = db.Column(db.String(20), nullable=False, default=ROLE_CLIENT)
    store_id = db.Column(db.Integer, db.ForeignKey("store.id"))
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    login_code_hash = db.Column(db.String(255))
    login_code_expires = db.Column(db.DateTime)
    login_code_attempts = db.Column(db.Integer, nullable=False, default=0)

    store = db.relationship("Store", back_populates="staff")
    appointments = db.relationship("Appointment", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN

    @property
    def is_staff(self):
        return self.role in (ROLE_ADMIN, ROLE_STORE_ADMIN)

    @property
    def display_name(self):
        return self.name or self.email

    def can_manage(self, store):
        return self.is_admin or (self.role == ROLE_STORE_ADMIN and self.store_id == store.id)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    store_id = db.Column(db.Integer, db.ForeignKey("store.id"), nullable=False)
    # Wall-clock time at the store (naive); see Store.now_local.
    starts_at = db.Column(db.DateTime, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default=STATUS_BOOKED)
    notes = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    user = db.relationship("User", back_populates="appointments")
    store = db.relationship("Store", back_populates="appointments")

    __table_args__ = (
        # The database itself guarantees a client never holds two open bookings.
        Index(
            "uq_one_open_appointment_per_user", "user_id", unique=True,
            sqlite_where=text("status = 'booked'"),
            postgresql_where=text("status = 'booked'"),
        ),
        Index("ix_appointment_store_start", "store_id", "starts_at"),
    )

    @property
    def ends_at(self):
        return self.starts_at + timedelta(minutes=self.duration_minutes)

    @property
    def status_label(self):
        return STATUSES.get(self.status, self.status)

    def is_stale(self):
        return self.status == STATUS_BOOKED and self.ends_at + STALE_AFTER < self.store.now_local()
