from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
import requests
import secrets
from datetime import datetime, timedelta
import os

from ..config import (
    RECAPTCHA_SITE_KEY,
    RECAPTCHA_SECRET_KEY,
    DEV_SKIP_RECAPTCHA,
    logger,
)
from ..database import (
    users_collection,
    logins_collection,
    password_resets_collection,
)
from ..security import (
    pwd_context,
    create_session_record,
    create_access_token,
)
from ..email_utils import send_email
from ..kafka_logger import log_user_activity, log_event

router = APIRouter()

# =========================================================
# LOGIN
# =========================================================

@router.get("/login", response_class=HTMLResponse)
def get_login(request: Request):
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "site_key": RECAPTCHA_SITE_KEY,
            "flash": flash,
        },
    )


@router.post("/login")
async def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response"),
):
    logger.info("Login form submitted")

    # -----------------------------------------------------
    # 1. reCAPTCHA
    # -----------------------------------------------------
    if not DEV_SKIP_RECAPTCHA:
        try:
            r = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": RECAPTCHA_SECRET_KEY,
                    "response": g_recaptcha_response,
                },
                timeout=10,
            )
            if not r.json().get("success"):
                request.session["flash"] = "reCAPTCHA failed."
                return RedirectResponse("/login", status_code=302)
        except Exception:
            request.session["flash"] = "reCAPTCHA verification failed."
            return RedirectResponse("/login", status_code=302)

    # -----------------------------------------------------
    # 2. USER LOOKUP
    # -----------------------------------------------------
    user = users_collection.find_one({"email": username})
    if not user:
        request.session["flash"] = "Invalid credentials."
        return RedirectResponse("/login", status_code=302)

    hashed_password = (
        user.get("password_hash")
        or user.get("password")
        or user.get("hashed_password")
    )

    if not hashed_password or not pwd_context.verify(password, hashed_password):
        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.utcnow(),
            "status": "failed",
        })
        try:
            log_user_activity(username, "login_failed")
        except Exception:
            logger.exception("Kafka login_failed log failed")

        request.session["flash"] = "Invalid credentials."
        return RedirectResponse("/login", status_code=302)

    role = user.get("role", "user")

    # -----------------------------------------------------
    # 3. LOGIN SUCCESS LOGGING
    # -----------------------------------------------------
    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.utcnow(),
        "status": "success",
    })

    # -----------------------------------------------------
    # 4. ADMIN → NO MFA (IMPORTANT)
    # -----------------------------------------------------
    if role == "admin":
        try:
            log_user_activity(username, "admin_login_success")
            log_event("admin_login", f"Admin {username} logged in")
        except Exception:
            logger.exception("Kafka admin login logging failed")

        session_info = create_session_record(username)
        access_token = create_access_token(
            {"sub": username, "role": role},
            session_id=session_info["session_id"],
        )

        request.session["access_token"] = access_token
        request.session["session_id"] = session_info["session_id"]
        request.session["role"] = role
        request.session["username"] = username

        return RedirectResponse("/admin-dashboard", status_code=302)

    # -----------------------------------------------------
    # 5. USER → MFA FLOW
    # -----------------------------------------------------
    mfa_info = user.get("mfa", {})

    if mfa_info.get("enabled"):
        try:
            log_user_activity(username, "login_password_verified")
            log_event("mfa_pending", f"User {username} awaiting MFA")
        except Exception:
            logger.exception("Kafka MFA pending log failed")

        request.session["pending_mfa_email"] = username
        request.session["pending_mfa_role"] = role
        request.session["pending_mfa_name"] = user.get("name", "")
        request.session["flash"] = "Enter your MFA code."

        return RedirectResponse("/mfa/relogin", status_code=302)

    # First-time user → MFA setup
    request.session["mfa_temp_user"] = username
    return RedirectResponse("/mfa/setup", status_code=302)


# =========================================================
# SIGNUP
# =========================================================

@router.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request):
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "signup.html",
        {"request": request, "flash": flash},
    )


# =========================================================
# FORGOT PASSWORD
# =========================================================

@router.get("/forgot-password", response_class=HTMLResponse)
def get_forgot_password(request: Request):
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "flash": flash},
    )


@router.post("/forgot-password")
def post_forgot_password(request: Request, email: str = Form(...)):
    user = users_collection.find_one({"email": email})

    if user:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=20)

        password_resets_collection.insert_one({
            "email": email,
            "token": token,
            "expires_at": expires_at,
        })

        frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:8000")
        reset_link = f"{frontend_url}/reset-password?token={token}"

        send_email(
            email,
            "Reset your SCMLite password",
            f"Click the link to reset your password:\n\n{reset_link}",
        )

    request.session["flash"] = "If the email exists, a reset link was sent."
    return RedirectResponse("/login", status_code=302)


# =========================================================
# RESET PASSWORD
# =========================================================

@router.get("/reset-password", response_class=HTMLResponse)
def get_reset_password(request: Request, token: str):
    record = password_resets_collection.find_one({"token": token})
    if not record or record["expires_at"] < datetime.utcnow():
        request.session["flash"] = "Invalid or expired reset link."
        return RedirectResponse("/login", status_code=302)

    return request.app.state.templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "token": token},
    )


@router.post("/reset-password")
def post_reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    record = password_resets_collection.find_one({"token": token})

    if not record or record["expires_at"] < datetime.utcnow():
        request.session["flash"] = "Invalid or expired reset link."
        return RedirectResponse("/login", status_code=302)

    if new_password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse(f"/reset-password?token={token}", status_code=302)

    password_hash = pwd_context.hash(new_password)

    users_collection.update_one(
        {"email": record["email"]},
        {"$set": {"password_hash": password_hash}},
    )

    password_resets_collection.delete_one({"token": token})

    request.session["flash"] = "Password reset successful. Please login."
    return RedirectResponse("/login", status_code=302)
