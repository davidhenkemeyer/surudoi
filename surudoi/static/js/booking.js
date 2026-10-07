// Store page: pick a day, pick a time, confirm.
(function () {
  var chips = Array.prototype.slice.call(document.querySelectorAll(".day-chip"));
  var panels = document.querySelectorAll("[data-day-panel]");
  var bar = document.getElementById("confirm-bar");
  var startInput = document.getElementById("starts-at");
  var label = document.getElementById("selected-label");
  var signIn = document.getElementById("signin-to-book");
  if (!chips.length || !bar) return;

  function showDay(day) {
    chips.forEach(function (c) {
      var on = c.dataset.day === day;
      c.classList.toggle("selected", on);
      c.setAttribute("aria-selected", on ? "true" : "false");
    });
    panels.forEach(function (p) { p.hidden = p.dataset.dayPanel !== day; });
  }

  function choose(slot) {
    document.querySelectorAll(".slot.selected").forEach(function (s) { s.classList.remove("selected"); });
    slot.classList.add("selected");
    if (startInput) startInput.value = slot.dataset.start;
    label.textContent = slot.dataset.label;
    bar.hidden = false;
    if (signIn) {
      // Keep the chosen time across the sign-in round trip.
      var next = new URL(window.location.href);
      next.searchParams.set("slot", slot.dataset.start);
      var href = new URL(signIn.dataset.base, window.location.origin);
      href.searchParams.set("next", next.pathname + next.search);
      signIn.href = href.pathname + href.search;
    }
  }

  chips.forEach(function (c) {
    c.addEventListener("click", function () { if (!c.disabled) showDay(c.dataset.day); });
  });
  document.querySelectorAll(".slot").forEach(function (s) {
    s.addEventListener("click", function () { choose(s); });
  });

  // Preselect a slot passed in the URL (after signing in), else the first open day.
  var wanted = new URLSearchParams(window.location.search).get("slot");
  var preset = wanted && document.querySelector('.slot[data-start="' + wanted.replace(/"/g, "") + '"]');
  if (preset) {
    showDay(preset.closest("[data-day-panel]").dataset.dayPanel);
    choose(preset);
    preset.scrollIntoView({ block: "center" });
  } else {
    var first = chips.find(function (c) { return !c.disabled; });
    if (first) showDay(first.dataset.day);
  }
})();
