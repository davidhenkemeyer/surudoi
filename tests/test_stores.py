import io

from surudoi.models import Store
from surudoi.stores import export_stores, import_stores

from .conftest import login, make_store, post

LEGACY_CSV = """Location,Address,City,State,Zip,MondayOpen,MondayClose,TuesdayOpen,TuesdayClose,WednesdayOpen,WednesdayClose,ThursdayOpen,ThursdayClose,FridayOpen,FridayClose,SaturdayOpen,SaturdayClose,SundayOpen,SundayClose,Mon - Fri,Saturday,Sunday,Phone,Email
Pure Hockey #104,3225 Alderwood Mall Blvd. Unit A,Lynnwood,WA,98036,1100,1900,1100,1900,1100,1900,1100,1900,1100,1900,900,1800,,,11am - 7pm,9am - 6pm,10am - 5pm,425-835-0131,lynnwood@purehockey.com
Pure Hockey #148,"15829 N. 83rd Ave., Suite 101",Peoria,az,85382,1300,2000,1300,2000,1300,2000,1300,2000,1300,2000,900,1800,900,1800,1pm - 8pm,9am - 6pm,9am - 6pm,623-412-3377,peoria@purehockey.com
"""


def test_imports_legacy_purehockey_format(app):
    result = import_stores(LEGACY_CSV, geocode=False)
    assert (result.created, result.errors) == (2, [])
    lynnwood = Store.query.filter_by(name="Pure Hockey #104").one()
    assert lynnwood.hours["mon"] == ["11:00", "19:00"]
    assert lynnwood.hours["sat"] == ["09:00", "18:00"]
    assert "sun" not in lynnwood.hours  # blank open/close = closed
    assert lynnwood.timezone == "America/Los_Angeles"
    peoria = Store.query.filter_by(name="Pure Hockey #148").one()
    assert peoria.state == "AZ" and peoria.timezone == "America/Phoenix"
    assert peoria.address == "15829 N. 83rd Ave., Suite 101"


def test_flexible_headers_price_and_upsert(app):
    import_stores("Store Name,Street Address,City,State,ZIP Code,Cost,Duration,Capacity,lat,lng,Monday\n"
                  "Spa One,1 A St,Denver,CO,80202,$45.00,60,3,39.7,-104.9,9am-5pm\n", geocode=False)
    spa = Store.query.one()
    assert (spa.price_cents, spa.slot_minutes, spa.capacity) == (4500, 60, 3)
    assert (spa.latitude, spa.longitude) == (39.7, -104.9)
    assert spa.hours == {"mon": ["09:00", "17:00"]}

    result = import_stores("Name,Price\nSpa One,50\n", geocode=False)
    assert (result.created, result.updated) == (0, 1)
    assert spa.price_cents == 5000 and spa.slot_minutes == 60  # untouched columns kept


def test_bad_rows_are_reported_not_fatal(app):
    result = import_stores("Name,Address,Price,MondayOpen,MondayClose\n"
                           "Good,1 A St,10,9am,5pm\n"
                           "Bad Price,2 B St,lots,9am,5pm\n"
                           "Bad Hours,3 C St,10,5pm,9am\n"
                           "No Address,,10,9am,5pm\n", geocode=False)
    assert result.created == 1
    assert len(result.errors) == 3
    assert [s.name for s in Store.query.all()] == ["Good"]


def test_missing_name_column(app):
    result = import_stores("Address,City\n1 A St,Denver\n", geocode=False)
    assert result.errors and result.created == 0


def test_export_round_trips(app):
    import_stores(LEGACY_CSV, geocode=False)
    exported = export_stores()
    Store.query.delete()
    result = import_stores(exported, geocode=False)
    assert result.created == 2 and not result.errors
    assert Store.query.filter_by(name="Pure Hockey #104").one().hours["fri"] == ["11:00", "19:00"]


def test_admin_csv_upload(client, admin):
    login(client, admin)
    r = client.post("/admin/stores/import", data={
        "csrf_token": "test-csrf-token",
        "file": (io.BytesIO(LEGACY_CSV.encode("utf-8-sig")), "stores.csv"),
    }, content_type="multipart/form-data")
    assert r.status_code == 302
    assert Store.query.count() == 2


def test_nearby_api_uses_radius(client):
    make_store("Seattle", lat=47.61, lng=-122.33)
    make_store("Tacoma", lat=47.25, lng=-122.44)       # ~25 mi
    make_store("Portland", lat=45.52, lng=-122.68)     # ~145 mi
    make_store("Hidden", lat=47.6, lng=-122.3, active=False)
    data = client.get("/api/stores/near?lat=47.61&lng=-122.33").get_json()
    assert data["within_radius"] is True
    assert [s["name"] for s in data["stores"]] == ["Seattle", "Tacoma"]
    assert data["stores"][0]["next_available"]

    far = client.get("/api/stores/near?lat=40.7&lng=-74.0").get_json()
    assert far["within_radius"] is False and len(far["stores"]) == 3


def test_admin_store_form(client, admin):
    login(client, admin)
    form = {"name": "New Spot", "address": "9 Elm St", "city": "Austin", "state": "TX", "zip_code": "78701",
            "latitude": "30.27", "longitude": "-97.74", "price": "15", "slot_minutes": "30", "capacity": "1",
            "active": "1", "open_tue": "1", "tue_open": "10:00", "tue_close": "16:00"}
    assert post(client, "/admin/stores/new", **form).status_code == 302
    s = Store.query.one()
    assert s.timezone == "America/Chicago" and s.hours == {"tue": ["10:00", "16:00"]}

    form["name"] = ""
    assert post(client, f"/admin/stores/{s.id}/edit", **form).status_code == 400
    assert Store.query.one().name == "New Spot"
