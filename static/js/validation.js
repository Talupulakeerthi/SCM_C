/* ===========================================================
   GLOBAL VALIDATION ENGINE – Works for ALL forms
   =========================================================== */

/* ---------- Helper Functions ---------- */

function $(id) {
  return document.getElementById(id);
}

function isEmpty(el) {
  return !el || el.value.trim() === "";
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidDate(str) {
  const d = new Date(str);
  return !isNaN(d.getTime());
}

function showError(el, message) {
  clearError(el);

  const container = el.parentElement;
  const err = document.createElement("div");
  err.className = "form-error";
  err.innerText = message;

  el.classList.add("input-error");
  container.appendChild(err);
}

function clearError(el) {
  if (!el) return;
  el.classList.remove("input-error");

  const err = el.parentElement.querySelector(".form-error");
  if (err) err.remove();
}

function disableSubmit(form) {
  const btn = form.querySelector("button[type=submit]");
  if (btn) btn.disabled = true;
}

function enableSubmit(form) {
  const btn = form.querySelector("button[type=submit]");
  if (btn) btn.disabled = false;
}

/* ---------- Core Validator Runner ---------- */

function runValidators(validators, form, event) {
  let ok = true;

  validators.forEach(v => {
    clearError(v.el);
    if (!v.fn()) {
      ok = false;
      showError(v.el, v.msg);
    }
  });

  if (!ok) {
    event.preventDefault();
    enableSubmit(form);
  } else {
    disableSubmit(form);
  }

  return ok;
}

/* ===========================================================
   FORM-BASED VALIDATION SETS
   =========================================================== */

/* ---------- LOGIN FORM ---------- */
function validateLoginForm(ev) {
  const form = ev.target;

  const email = $("username");
  const pass = $("password");

  return runValidators([
    { el: email, fn: () => !isEmpty(email) && isValidEmail(email.value), msg: "Enter a valid email." },
    { el: pass, fn: () => !isEmpty(pass) && pass.value.length >= 4, msg: "Password must be at least 4 characters." }
  ], form, ev);
}

/* ---------- SIGNUP FORM ---------- */
function validateSignup(ev) {
  const form = ev.target;

  const name = $("fullname");
  const email = $("email");
  const pass = $("password");
  const confirm = $("confirm_password");

  return runValidators([
    { el: name, fn: () => !isEmpty(name), msg: "Full name is required." },
    { el: email, fn: () => isValidEmail(email.value), msg: "Enter a valid email." },
    { el: pass, fn: () => pass.value.length >= 6, msg: "Password must be 6+ characters." },
    { el: confirm, fn: () => pass.value === confirm.value, msg: "Passwords do not match." }
  ], form, ev);
}

/* ---------- FORGOT PASSWORD FORM ---------- */
function validateForgot(ev) {
  const form = ev.target;
  const email = $("email");
  return runValidators([
    { el: email, fn: () => isValidEmail(email.value), msg: "Enter a valid email." }
  ], form, ev);
}

/* ---------- RESET PASSWORD FORM ---------- */
function validateReset(ev) {
  const form = ev.target;
  const pass = $("new_password");
  const confirm = $("confirm_password");

  return runValidators([
    { el: pass, fn: () => pass.value.length >= 6, msg: "Password must be 6+ characters." },
    { el: confirm, fn: () => pass.value === confirm.value, msg: "Passwords must match." }
  ], form, ev);
}

/* ---------- CREATE SHIPMENT ---------- */
function validateShipment(ev) {
  const form = ev.target;

  const fields = [
    { id: "shipment_id", len: 3 },
    { id: "po_number", len: 1 },
    { id: "route_details", len: 3 },
    { id: "device", len: 1 },
    { id: "ndc_number", len: 1 },
    { id: "serial_number", len: 1 },
    { id: "container_number", len: 1 },
    { id: "goods_type", len: 1 },
    { id: "expected_delivery_date", date: true },
    { id: "delivery_number", len: 1 },
    { id: "batch_id", len: 1 },
    { id: "origin", len: 1 },
    { id: "destination", len: 1 },
    { id: "status", len: 1 },
    { id: "shipment_description", len: 10 }
  ];

  const validators = fields.map(f => {
    const el = $(f.id);
    return {
      el,
      fn: () => {
        if (f.date) return isValidDate(el.value);
        return el.value.trim().length >= f.len;
      },
      msg: `${f.id.replace(/_/g, " ")} is required.`
    };
  });

  return runValidators(validators, form, ev);
}

/* ---------- EDIT USER FORM ---------- */
function validateEditUser(ev) {
  const name = $("name");
  const role = $("role");
  const form = ev.target;

  return runValidators([
    { el: name, fn: () => !isEmpty(name), msg: "Name cannot be empty." },
    { el: role, fn: () => !isEmpty(role), msg: "Select a role." }
  ], form, ev);
}

/* ===========================================================
   AUTO-ATTACH VALIDATION WHEN PAGE LOADS
   =========================================================== */

document.addEventListener("DOMContentLoaded", () => {
  const attach = (id, fn) => {
    const f = document.querySelector(id);
    if (f) f.addEventListener("submit", fn);
  };

  attach("#loginForm", validateLoginForm);
  attach("#signupForm", validateSignup);
  attach("#forgotForm", validateForgot);
  attach("#resetForm", validateReset);
  attach("#shipmentForm", validateShipment);
  attach("#editUserForm", validateEditUser);

  console.log("Validation engine loaded ✔");
});
