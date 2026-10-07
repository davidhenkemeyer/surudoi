// Small progressive enhancements shared by every page.
(function () {
  // <form data-confirm="Are you sure?">
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
      return;
    }
    var busy = form.querySelector("[data-busy]");
    if (busy) {
      busy.disabled = true;
      busy.textContent = busy.getAttribute("data-busy");
    }
  });

  // <select data-autosubmit> / <input data-autosubmit>
  document.addEventListener("change", function (e) {
    if (e.target.hasAttribute && e.target.hasAttribute("data-autosubmit")) e.target.form.submit();
  });

  // Store hours editor: disable the time inputs for closed days.
  document.querySelectorAll("[data-hours-row]").forEach(function (row) {
    var toggle = row.querySelector("[data-hours-toggle]");
    var sync = function () {
      row.classList.toggle("is-closed", !toggle.checked);
      row.querySelectorAll("input[type=time]").forEach(function (i) { i.disabled = !toggle.checked; });
    };
    toggle.addEventListener("change", sync);
    sync();
  });

  // User forms: only show the store picker for store admins.
  document.querySelectorAll("[data-role-form]").forEach(function (form) {
    var select = form.querySelector("[data-role-select]");
    var field = form.querySelector("[data-store-field]");
    var sync = function () { field.hidden = select.value !== "store_admin"; };
    select.addEventListener("change", sync);
    sync();
  });

  // Auto-dismiss success messages.
  document.querySelectorAll(".flash-success").forEach(function (el) {
    setTimeout(function () { el.classList.add("fade"); }, 6000);
  });
})();
