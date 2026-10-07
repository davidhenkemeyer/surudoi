// Store finder: locate the user, show stores within the search radius on a map.
(function () {
  var mapEl = document.getElementById("map");
  if (!mapEl || !window.L) return;

  var RADIUS_MILES = parseFloat(mapEl.dataset.radius) || 50;
  var METERS_PER_MILE = 1609.344;
  var BRAND = getComputedStyle(document.documentElement).getPropertyValue("--brand").trim() || "#1f5eff";
  var statusEl = document.getElementById("finder-status");
  var listEl = document.getElementById("store-list");
  var searchForm = document.getElementById("place-search");
  var locateBtn = document.getElementById("use-location");

  var map = L.map(mapEl, { zoomControl: true, scrollWheelZoom: true }).setView([39.5, -98.35], 4);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 18,
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  }).addTo(map);

  var layer = L.layerGroup().addTo(map);
  var markers = {};

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function setStatus(html, tone) {
    statusEl.innerHTML = html;
    statusEl.className = "finder-status" + (tone ? " is-" + tone : "");
  }

  function pinIcon(n) {
    return L.divIcon({
      className: "pin",
      html: '<span class="pin-body"><span>' + n + "</span></span>",
      iconSize: [30, 38],
      iconAnchor: [15, 36],
      popupAnchor: [0, -32],
    });
  }

  var youIcon = L.divIcon({ className: "you-dot", html: "<span></span>", iconSize: [18, 18], iconAnchor: [9, 9] });

  function select(id, pan) {
    listEl.querySelectorAll(".store-item").forEach(function (li) {
      li.classList.toggle("selected", li.dataset.id === String(id));
    });
    var m = markers[id];
    if (m) {
      if (pan) map.panTo(m.getLatLng());
      m.openPopup();
    }
  }

  function render(origin, data, label) {
    layer.clearLayers();
    markers = {};
    listEl.innerHTML = "";

    L.marker([origin.lat, origin.lng], { icon: youIcon, interactive: false, keyboard: false }).addTo(layer);
    var circle = L.circle([origin.lat, origin.lng], {
      radius: RADIUS_MILES * METERS_PER_MILE,
      color: BRAND, weight: 1.5, fillOpacity: 0.06, interactive: false,
    }).addTo(layer);

    var stores = data.stores || [];
    if (!stores.length) {
      map.fitBounds(circle.getBounds());
      setStatus("No locations found yet. Try another search.", "warn");
      return;
    }

    var bounds = data.within_radius ? circle.getBounds() : L.latLngBounds([[origin.lat, origin.lng]]);
    stores.forEach(function (s, i) {
      var n = i + 1;
      var marker = L.marker([s.lat, s.lng], { icon: pinIcon(n), title: s.name }).addTo(layer);
      marker.bindPopup(
        '<div class="popup"><strong>' + esc(s.name) + "</strong><br>" + esc(s.address) +
          '<br><span class="muted">' + esc(s.distance_miles) + " mi · " + esc(s.price) + "</span>" +
          '<br><a class="btn btn-primary btn-sm" href="' + esc(s.url) + '">Book here</a></div>'
      );
      marker.on("click", function () { select(s.id, false); });
      markers[s.id] = marker;
      bounds.extend([s.lat, s.lng]);

      var li = document.createElement("li");
      li.className = "store-item";
      li.dataset.id = s.id;
      li.innerHTML =
        '<span class="store-num">' + n + "</span>" +
        '<div class="store-info">' +
          '<div class="store-line"><strong>' + esc(s.name) + '</strong><span class="distance">' + esc(s.distance_miles) + " mi</span></div>" +
          '<div class="muted small">' + esc(s.address) + ", " + esc(s.city_line) + "</div>" +
          '<div class="store-meta small">' +
            "<span>Today: " + esc(s.today_hours) + "</span>" +
            "<span>" + esc(s.price) + "</span>" +
          "</div>" +
          '<div class="store-cta">' +
            (s.next_available
              ? '<span class="next small">Next opening <strong>' + esc(s.next_available) + "</strong></span>"
              : '<span class="next small muted">No openings in the next two weeks</span>') +
            '<a class="btn btn-primary btn-sm" href="' + esc(s.url) + '">Book</a>' +
          "</div>" +
        "</div>";
      li.addEventListener("click", function (e) {
        if (e.target.closest("a")) return;
        select(s.id, true);
      });
      listEl.appendChild(li);
    });
    map.fitBounds(bounds, { padding: [24, 24] });

    var where = label ? " of " + esc(label) : "";
    if (data.within_radius) {
      setStatus("<strong>" + stores.length + "</strong> location" + (stores.length === 1 ? "" : "s") +
        " within " + RADIUS_MILES + " miles" + where + ".");
    } else {
      setStatus("No locations within " + RADIUS_MILES + " miles" + where + ". Here are the closest:", "warn");
    }
  }

  function loadNear(origin, label) {
    setStatus("Looking for nearby locations…");
    var url = mapEl.dataset.nearUrl + "?lat=" + origin.lat + "&lng=" + origin.lng;
    fetch(url)
      .then(function (r) { return r.json(); })
      .then(function (data) { render(origin, data, label); })
      .catch(function () { setStatus("Something went wrong loading stores. Please try again.", "error"); });
  }

  function locate() {
    if (!navigator.geolocation) {
      setStatus("Your browser can't share its location. Search for a city or ZIP code instead.", "warn");
      return;
    }
    setStatus("Finding your location…");
    navigator.geolocation.getCurrentPosition(
      function (pos) {
        loadNear({ lat: pos.coords.latitude, lng: pos.coords.longitude }, null);
      },
      function () {
        setStatus("We couldn't get your location. Search for a city or ZIP code above.", "warn");
        searchForm.querySelector("input").focus();
      },
      { enableHighAccuracy: false, timeout: 10000, maximumAge: 600000 }
    );
  }

  searchForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var q = searchForm.q.value.trim();
    if (!q) return;
    setStatus("Searching for " + esc(q) + "…");
    fetch(mapEl.dataset.placesUrl + "?q=" + encodeURIComponent(q))
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (!res.ok) { setStatus(esc(res.body.error), "warn"); return; }
        loadNear({ lat: res.body.lat, lng: res.body.lng }, q);
      })
      .catch(function () { setStatus("Search isn't working right now. Please try again.", "error"); });
  });

  locateBtn.addEventListener("click", locate);
  locate();
})();
