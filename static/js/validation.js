// =====================================================================
// EMAIL VALIDATION HELPER
// =====================================================================
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// =====================================================================
// LOGIN PAGE VALIDATION
// =====================================================================
function validateLoginForm() {
    const email = document.getElementById("username")?.value.trim();
    const password = document.getElementById("password")?.value.trim();

    if (!email || !isValidEmail(email)) {
        alert("Please enter a valid email address.");
        return false;
    }
    if (!password || password.length < 4) {
        alert("Password must be at least 4 characters.");
        return false;
    }
    return true;
}

// =====================================================================
// SIGNUP PAGE VALIDATION
// =====================================================================
function validateSignupForm() {
    const name = document.getElementById("fullname")?.value.trim();
    const email = document.getElementById("email")?.value.trim();
    const pass = document.getElementById("password")?.value;
    const confirm = document.getElementById("confirm_password")?.value;

    if (!name) {
        alert("Full name is required.");
        return false;
    }
    if (!email || !isValidEmail(email)) {
        alert("Enter a valid email address.");
        return false;
    }
    if (!pass || pass.length < 6) {
        alert("Password must be at least 6 characters.");
        return false;
    }
    if (pass !== confirm) {
        alert("Passwords do not match.");
        return false;
    }
    return true;
}

// =====================================================================
// FORGOT PASSWORD VALIDATION
// =====================================================================
function validateForgotPasswordForm() {
    const email = document.getElementById("email")?.value.trim();

    if (!email || !isValidEmail(email)) {
        alert("Enter a valid email address.");
        return false;
    }
    return true;
}

// =====================================================================
// RESET PASSWORD VALIDATION
// =====================================================================
function validateResetPassword() {
    const pass = document.getElementById("new_password")?.value;
    const confirm = document.getElementById("confirm_password")?.value;

    if (!pass || pass.length < 6) {
        alert("Password must be at least 6 characters.");
        return false;
    }
    if (pass !== confirm) {
        alert("Passwords do not match.");
        return false;
    }
    return true;
}

// =====================================================================
// TOGGLE PASSWORD VISIBILITY
// =====================================================================
function togglePwd(id, btn) {
    const input = document.getElementById(id);
    const icon = btn.querySelector("i");

    input.type = input.type === "password" ? "text" : "password";
    icon.classList.toggle("fa-eye");
    icon.classList.toggle("fa-eye-slash");
}

// =====================================================================
// CREATE SHIPMENT VALIDATION
// =====================================================================
function validateShipmentForm() {
    const requiredFields = [
        "shipment_id",
        "po_number",
        "route_details",
        "device",
        "ndc_number",
        "serial_number",
        "container_number",
        "goods_type",
        "expected_delivery_date",
        "delivery_number",
        "batch_id",
        "origin",
        "destination",
        "status",
        "shipment_description"
    ];

    for (let id of requiredFields) {
        const field = document.getElementById(id);
        if (!field || field.value.trim() === "") {
            alert(`Please fill out: ${id.replace(/_/g, " ").toUpperCase()}`);
            field.focus();
            return false;
        }
    }

    if (document.getElementById("shipment_description").value.trim().length < 10) {
        alert("Shipment description must be at least 10 characters.");
        return false;
    }

    return true;
}

// =====================================================================
// EDIT USER VALIDATION
// =====================================================================
function validateEditUserForm() {
    const name = document.getElementById("name")?.value.trim();
    const role = document.getElementById("role")?.value.trim();

    if (!name) {
        alert("Name cannot be empty.");
        return false;
    }
    if (!role) {
        alert("Please select a role.");
        return false;
    }
    return true;
}
