"""Distance math and free geocoding (US Census, falling back to OpenStreetMap)."""
import json
import logging
import math
import time
import urllib.parse
import urllib.request
from functools import lru_cache

from flask import current_app

log = logging.getLogger(__name__)

USER_AGENT = "surudoi-booking/1.0"
EARTH_RADIUS_MILES = 3958.8

STATE_TIMEZONES = {
    "AL": "America/Chicago", "AK": "America/Anchorage", "AZ": "America/Phoenix",
    "AR": "America/Chicago", "CA": "America/Los_Angeles", "CO": "America/Denver",
    "CT": "America/New_York", "DE": "America/New_York", "DC": "America/New_York",
    "FL": "America/New_York", "GA": "America/New_York", "HI": "Pacific/Honolulu",
    "ID": "America/Boise", "IL": "America/Chicago", "IN": "America/Indiana/Indianapolis",
    "IA": "America/Chicago", "KS": "America/Chicago", "KY": "America/New_York",
    "LA": "America/Chicago", "ME": "America/New_York", "MD": "America/New_York",
    "MA": "America/New_York", "MI": "America/Detroit", "MN": "America/Chicago",
    "MS": "America/Chicago", "MO": "America/Chicago", "MT": "America/Denver",
    "NE": "America/Chicago", "NV": "America/Los_Angeles", "NH": "America/New_York",
    "NJ": "America/New_York", "NM": "America/Denver", "NY": "America/New_York",
    "NC": "America/New_York", "ND": "America/Chicago", "OH": "America/New_York",
    "OK": "America/Chicago", "OR": "America/Los_Angeles", "PA": "America/New_York",
    "RI": "America/New_York", "SC": "America/New_York", "SD": "America/Chicago",
    "TN": "America/Chicago", "TX": "America/Chicago", "UT": "America/Denver",
    "VT": "America/New_York", "VA": "America/New_York", "WA": "America/Los_Angeles",
    "WV": "America/New_York", "WI": "America/Chicago", "WY": "America/Denver",
}


def timezone_for_state(state, default="America/New_York"):
    return STATE_TIMEZONES.get((state or "").strip().upper(), default)


def distance_miles(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_MILES * math.asin(math.sqrt(a))


def _get_json(url, params):
    req = urllib.request.Request(
        f"{url}?{urllib.parse.urlencode(params)}", headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.load(resp)


def _census(address):
    data = _get_json(
        "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress",
        {"address": address, "benchmark": "Public_AR_Current", "format": "json"},
    )
    matches = data.get("result", {}).get("addressMatches") or []
    if matches:
        c = matches[0]["coordinates"]
        return c["y"], c["x"]
    return None


_last_nominatim = 0.0


def _nominatim(query):
    # OpenStreetMap's usage policy allows at most one request per second.
    global _last_nominatim
    wait = 1.0 - (time.monotonic() - _last_nominatim)
    if wait > 0:
        time.sleep(wait)
    _last_nominatim = time.monotonic()
    data = _get_json(
        "https://nominatim.openstreetmap.org/search",
        {"q": query, "format": "json", "limit": 1, "countrycodes": "us,ca"},
    )
    if data:
        return float(data[0]["lat"]), float(data[0]["lon"]), data[0].get("display_name", query)
    return None


def geocode_address(address, city="", state="", zip_code=""):
    """Street address -> (lat, lng) or None. Never raises."""
    if not current_app.config.get("GEOCODING_ENABLED", True):
        return None
    full = ", ".join(p for p in (address, city, f"{state} {zip_code}".strip()) if p)
    try:
        result = _census(full)
        if result:
            return result
    except Exception as e:  # network trouble shouldn't break an import
        log.warning("Census geocoder failed for %r: %s", full, e)
    for query in (full, ", ".join(p for p in (city, state, zip_code) if p)):
        try:
            hit = _nominatim(query)
            if hit:
                return hit[0], hit[1]
        except Exception as e:
            log.warning("Nominatim failed for %r: %s", query, e)
    return None


@lru_cache(maxsize=512)
def _search_cached(query):
    hit = _nominatim(query)
    return {"lat": hit[0], "lng": hit[1], "label": hit[2]} if hit else None


def search_place(query):
    """Free-text place ('Denver', '98036') -> {lat, lng, label} or None."""
    query = " ".join(query.split())[:120]
    if not query or not current_app.config.get("GEOCODING_ENABLED", True):
        return None
    try:
        return _search_cached(query.lower())
    except Exception as e:
        log.warning("Place search failed for %r: %s", query, e)
        return None
