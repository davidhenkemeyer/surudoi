# Surudoi

A small, rebrandable appointment booking app. It's set up for Pure Hockey skate sharpening, but works for anything with locations and time slots (massages, nails, repairs…). There are no payments; it only takes bookings.

- **Clients** sign in with just an email, see a map of locations within 50 miles of where they are (or a city/ZIP they search), pick a day and time, and book. Each client can hold **one open appointment** at a time. They can cancel it, or move it to another time or store.
- **Store admins** see their store's appointments day by day. They mark each one complete, no-show or canceled, and edit their store's hours, price, appointment length and capacity.
- **Global admins** add, edit and hide stores, import and export the store list as CSV, and manage users (assign store admins, block abusers).

## Quick start

```bash
python -m venv .venv
.venv/Scripts/activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt

flask --app app import-stores data/stores.csv
flask --app app add-user you@example.com --role admin
flask --app app run --debug
```

Open http://127.0.0.1:5000. The browser only shares your location on `localhost` or HTTPS. Elsewhere, clients can search by city or ZIP instead.

Admins sign in with a 6-digit code emailed to them. If email isn't configured yet, the code is printed in the server console, and in `--debug` mode it also appears on the page.

## The store CSV

Import it from **Admin → Stores → Import**, or run `flask --app app import-stores file.csv`. Rows are matched to existing stores **by name**: new names are added and existing ones are updated. Header names are flexible (`Zip`, `ZIP Code` and `zip_code` all work). Bad rows are reported and skipped; they don't abort the import.

| Column | Notes |
|---|---|
| `Name` *(required)* | Also accepts `Location`, `Store` |
| `Address` *(required for new stores)*, `City`, `State`, `Zip` | |
| `Phone`, `Email`, `Notes` | Notes are shown to clients on the booking page |
| `Price` | e.g. `10`, `$12.50`; blank keeps the current value (new stores use the site default) |
| `SlotMinutes` | Appointment length |
| `Capacity` | How many bookings can share one time slot |
| `Latitude`, `Longitude` | Optional; looked up automatically from the address if missing |
| `Timezone` | Optional; worked out from the state (e.g. `America/Denver`) |
| `Active` | `yes`/`no`; `no` hides the store from clients |
| `MondayOpen`, `MondayClose`, … `SundayClose` | `1100`, `11:00` or `11am`. Blank or `closed` = closed that day. A single `Monday` column with `11am - 7pm` also works |

`data/stores.csv` is the original Pure Hockey list (`data/purehockey_original.csv`) with coordinates, time zones, and placeholder price and slot settings ($10, 15 min, 2 per slot) filled in. **Replace the placeholders with real values.** The easiest way: download the CSV from the admin page, edit it in a spreadsheet, and import it back.

Addresses are geocoded with the free US Census geocoder, falling back to OpenStreetMap. Neither needs an API key.

## Rebranding

Edit `site.json` (or point `SITE_CONFIG` at another file):

```json
{
  "brand":   { "name": "Glow Spa", "app_name": "Glow Spa Booking", "tagline": "Book a massage near you",
               "service": "Massage", "logo_text": "GS", "primary_color": "#7c3aed" },
  "booking": { "search_radius_miles": 25, "days_ahead": 21, "min_lead_minutes": 120,
               "default_price": 90, "default_slot_minutes": 60, "default_capacity": 1,
               "notes_prompt": "Anything we should know?" },
  "auth":    { "email_codes_for": "admins" }
}
```

`auth.email_codes_for` decides who must enter an emailed code at sign-in:

- `"none"`: email only, for everyone.
- `"admins"` (default): store and global admins need a code; clients don't.
- `"everyone"`: everyone needs a code.

## Configuration (environment variables)

| Variable | Default | |
|---|---|---|
| `SECRET_KEY` | generated into `instance/secret_key` | Set this in production |
| `DATABASE_URL` | `sqlite:///instance/surudoi.db` | |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | unset | Needed to email sign-in codes |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` when served over HTTPS |
| `GEOCODING_ENABLED` | `1` | |

## Anti-abuse rules

- A client can hold only one open appointment. The database enforces this with a partial unique index, so it holds even if two requests race. Rebooking moves the existing appointment rather than adding a second.
- A store can't be overbooked past its capacity, and bookings must land on a real slot inside opening hours, within the booking window and at least `min_lead_minutes` away.
- Store admins can see each client's no-show count. Global admins can **block** a user, which cancels their open appointment and stops them from signing in.
- If a store never closes out an appointment, it stops counting as the client's open booking 3 hours after it ends. That way a client never gets locked out because the store forgot to close it.

## Other commands

```bash
flask --app app export-stores out.csv     # re-importable CSV of every store
flask --app app geocode-stores            # look up coordinates for stores missing them
flask --app app add-user mgr@example.com --role store_admin --store "Pure Hockey #104"
python -m pytest                          # run the tests
```

## Production notes

- Run behind a real WSGI server and HTTPS, for example `pip install waitress && waitress-serve --port 8000 app:app`.
- Map tiles come from openstreetmap.org, which is fine for light use. For heavier traffic, switch the tile URL in `surudoi/static/js/finder.js` to a hosted provider such as MapTiler or Stadia.
