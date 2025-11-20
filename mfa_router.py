# main/mfa_router.py
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from pymongo.collection import Collection
from datetime import datetime

# Import the helpers. If you run app directly (python app.py), use absolute import:
from mfa_service import new_secret, provisioning_uri, verify_code, qr_png
# If you switch to package mode (uvicorn main.app:app), change to:
# from .mfa_service import new_secret, provisioning_uri, verify_code, qr_png

router = APIRouter(prefix="/mfa", tags=["MFA"])

_templates: Jinja2Templates | None = None
_users: Collection | None = None

def init(
    templates: Jinja2Templates,
    users_collection: Collection,
    logins_collection: Collection,
    create_session_record_func=None,
    create_access_token_func=None,
) -> None:
    global _templates, _users, _logins, _create_session_record, _create_access_token
    _templates = templates
    _users = users_collection
    _logins = logins_collection
    _create_session_record = create_session_record_func
    _create_access_token = create_access_token_func

def _require_stage(request: Request) -> str:
    email = request.session.get("mfa_temp_user")
    if not email:
        raise HTTPException(status_code=401, detail="No pending MFA user")
    return email

@router.get("/setup", response_class=HTMLResponse)
def mfa_setup(request: Request):
    email = _require_stage(request)
    user = _users.find_one({"email": email})
    if not user:
        return RedirectResponse("/", 302)

    mfa = user.get("mfa") or {}
    secret = mfa.get("secret")
    if not secret:
        secret = new_secret()
        _users.update_one({"email": email}, {"$set": {"mfa": {"enabled": False, "secret": secret}}})

    uri = provisioning_uri(email, secret)
    return _templates.TemplateResponse(
        "mfa_setup.html",
        {"request": request, "email": email, "secret": secret, "otpauth_uri": uri}
    )

@router.get("/qrcode.png")
def mfa_qr(request: Request):
    email = _require_stage(request)
    user = _users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    secret = (user.get("mfa") or {}).get("secret")
    if not secret:
        raise HTTPException(status_code=400, detail="MFA secret missing")
    return Response(content=qr_png(provisioning_uri(email, secret)), media_type="image/png")

@router.post("/enable")
def mfa_enable(request: Request, code: str = Form(...)):
    email = _require_stage(request)
    user = _users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    secret = (user.get("mfa") or {}).get("secret")
    if not secret:
        raise HTTPException(status_code=400, detail="MFA secret missing")

    if verify_code(secret, code):
        _users.update_one({"email": email}, {"$set": {"mfa.enabled": True, "mfa.enabled_at": datetime.utcnow()}})
        request.session["mfa_verified"] = True
        return RedirectResponse("/mfa/finish", 302)
    raise HTTPException(status_code=401, detail="Invalid code")

@router.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request):
    email = _require_stage(request)
    return _templates.TemplateResponse("verify_top.html", {"request": request, "email": email})

@router.post("/verify")
def verify_code_route(request: Request, code: str = Form(...)):
    email = _require_stage(request)
    user = _users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = (user.get("mfa") or {}).get("secret")
    if not secret:
        return RedirectResponse("/mfa/setup", 302)

    if verify_code(secret, code):
        request.session["mfa_verified"] = True
        return RedirectResponse("/mfa/finish", 302)
    raise HTTPException(status_code=401, detail="Invalid code")

@router.get("/finish")
def finish(request: Request):
    if not request.session.get("mfa_verified"):
        return RedirectResponse("/mfa/verify", 302)
    return RedirectResponse("/mfa/finalize", 302)


# ==========================================================
# ✅ Re-login MFA Verification Route (TOTP only)
# ==========================================================
from jose import jwt
from datetime import datetime, timedelta
import pyotp
import os
 
# Generate JWT locally (avoid circular import)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret_key")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    """Generate a short-lived JWT token for session authentication."""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.get("/relogin", response_class=HTMLResponse)
def get_verify_top(request: Request):
    """Re-login MFA verification page for users with authenticator app."""
    flash = request.session.pop("flash", None)
    email = request.session.get("pending_mfa_email")

    if not email:
        request.session["flash"] = "Please log in first."
        return RedirectResponse(url="/login", status_code=302)

    return _templates.TemplateResponse(
        "verify_top.html",
        {"request": request, "flash": flash, "email": email}
    )

@router.post("/relogin/verify")
def verify_relogin_mfa(request: Request, code: str = Form(...)):
    """Handles OTP verification when an existing user logs in."""
    email = request.session.get("pending_mfa_email")
    if not email:
        request.session["flash"] = "Session expired. Please log in again."
        return RedirectResponse("/login", status_code=302)

    user = _users.find_one({"email": email})
    if not user:
        request.session["flash"] = "User not found."
        return RedirectResponse("/login", status_code=302)

    secret = user.get("mfa", {}).get("secret")
    if not secret:
        request.session["flash"] = "MFA not set up for this account."
        return RedirectResponse("/login", status_code=302)

    # ✅ Verify 6-digit TOTP code from user's authenticator
        # ----------------------------
    # MFA Verified → Create session + JWT properly
    # ----------------------------
    session_info = _create_session_record(email)

    access_token = _create_access_token(
        {"sub": email, "role": user.get("role", "user")},
        session_id=session_info["session_id"]
    )

    request.session["access_token"] = access_token
    request.session["session_id"] = session_info["session_id"]
    request.session["role"] = user.get("role", "user")
    request.session["username"] = email
    request.session["mfa_verified"] = True

    # Log successful login
    _logins.insert_one({
        "email": email,
        "login_time": datetime.utcnow(),
        "status": "success"
    })

    return RedirectResponse("/dashboard", status_code=302)


# ==========================================================
# ✅ Finalize MFA Login — Handles Post-Verification Redirect
# ==========================================================

#from app import create_session_record, create_access_token, logins_collection, users_collection

@router.get("/finalize")
def finalize_mfa_login(request: Request):
    """Finalize login after MFA verification, create session + JWT."""
    email = request.session.get("pending_mfa_email")
    role = request.session.get("pending_mfa_role", "user")
    name = request.session.get("pending_mfa_name", "")

    if not email:
        request.session["flash"] = "Session expired. Please log in again."
        return RedirectResponse("/login", status_code=302)

    # ✅ Step 5: create a session record (stored in MongoDB)
    from app import create_session_record, create_access_token  # import locally to avoid circular import

    # Capture user device + IP (optional but useful)
    user_agent = request.headers.get("user-agent", "unknown")
    ip = request.client.host if hasattr(request, "client") and request.client else None

    # Create a session record (returns session_id, refresh_token, expires_at)
    session_info = create_session_record(email, user_agent=user_agent, ip=ip)

    # Create JWT access token with session ID embedded
    access_token = create_access_token(
        data={"sub": email, "role": role},
        session_id=session_info["session_id"]
    )

    # ✅ Save everything into current user session
    request.session["access_token"] = access_token
    request.session["refresh_token"] = session_info["refresh_token"]     # dev-only
    request.session["refresh_expires_at"] = session_info["expires_at"].isoformat()
    request.session["user"] = {"email": email, "role": role, "name": name}

    # Clean up MFA temp session data
    for key in ["pending_mfa_email", "pending_mfa_role", "pending_mfa_name", "mfa_verified"]:
        request.session.pop(key, None)

    # Redirect to appropriate dashboard
    if role == "admin":
        return RedirectResponse("/admin-dashboard", status_code=302)
    return RedirectResponse("/dashboard", status_code=302)
