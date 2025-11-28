# ==========================================================
# main/app.py  — imports
# ==========================================================
from fastapi import FastAPI, Request, Form, status, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.utils import get_openapi
from pymongo import MongoClient
import secrets

# MFA router (we’ll wire it up later)
from mfa.mfa_router import router as mfa_router, init as mfa_init
#user role change email function
from email_service import send_role_change_email



# ----------------------------------------------------------
# Standard libraries
# ----------------------------------------------------------
import os
import uuid
import hashlib
import secrets
import logging
import requests
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

# ----------------------------------------------------------
# Auth & security
# ----------------------------------------------------------
from passlib.context import CryptContext
from jose import JWTError, jwt          # python-jose
from dotenv import load_dotenv
from pydantic import BaseModel

from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

# ensure load_dotenv() already called above

def send_email(to_email: str, subject: str, body: str):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    logger.debug("send_email() -> %s", to_email)
    if not EMAIL_USER or not EMAIL_PASS:
        logger.warning("EMAIL_USER/PASS missing. Writing verification to sent_emails.log")
        with open("sent_emails.log", "a", encoding="utf-8") as f:
            f.write(f"TO: {to_email}\n{body}\n\n---\n")
        return

    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.set_debuglevel(1)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [to_email], msg.as_string())
        server.quit()
        logger.info("Email sent to %s", to_email)
    except Exception:
        logger.exception("Email send failed for %s", to_email)

# ---------------------------
# Logging Configuration
# ---------------------------
logger = logging.getLogger("app")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("app.log")
stream_handler = logging.StreamHandler()

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)



# ---------------------------
# Load environment variables
# ---------------------------
load_dotenv()

import re
import dns.resolver

# Strict-ish email regex (good balance)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")



def is_valid_email_format(email: str) -> bool:
    """Basic regex email format validation."""
    return bool(EMAIL_RE.match(email))

def has_mx_record(domain: str) -> bool:
    """Return True if domain has an MX record (i.e., can receive email)."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return False
    except Exception:
        # be conservative — return False if anything odd
        return False

def is_real_domain_email(email: str) -> bool:
    """Check format and that the domain has an MX record."""
    if not is_valid_email_format(email):
        return False
    domain = email.split("@", 1)[1].lower()
    return has_mx_record(domain)


EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

if not EMAIL_USER or not EMAIL_PASS:
    logger.warning("EMAIL_USER or EMAIL_PASS not set. Emails will fail.")

def send_email(to_email: str, subject: str, body: str):
    """
    Send verification/reset emails via Gmail SMTP.
    If EMAIL_USER/PASS not set or send fails, fallback to sent_emails.log for dev.
    """
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    logger.debug("send_email() -> to=%s subject=%s", to_email, subject)

    if not EMAIL_USER or not EMAIL_PASS:
        logger.warning("EMAIL_USER or EMAIL_PASS not set. Writing to sent_emails.log instead.")
        with open("sent_emails.log", "a", encoding="utf-8") as f:
            f.write(f"--- TO: {to_email} SUBJECT: {subject} ---\n{body}\n\n")
        return

    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.set_debuglevel(1)    # print debug conversation in terminal
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [to_email], msg.as_string())
        server.quit()
        logger.info("Email sent to %s", to_email)
    except Exception:
        logger.exception("Failed to send email to %s. Check EMAIL_USER/PASS and network.", to_email)
        with open("sent_emails.log", "a", encoding="utf-8") as f:
            f.write(f"FAILED_SEND -> TO: {to_email} SUBJECT: {subject}\n{body}\n\n")


SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10"))

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("MONGO_DB_NAME", "SCMLiteDB")
DEV_SKIP_RECAPTCHA = os.getenv("DEV_SKIP_RECAPTCHA", "false").lower() == "true"


if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    raise ValueError(
        "Missing critical environment variables. "
        "Ensure JWT_SECRET_KEY, JWT_ALGORITHM, RECAPTCHA_SITE_KEY, "
        "RECAPTCHA_SECRET_KEY, and MONGO_URI are set in .env"
    )

# ---------------------------
# Initialize app
# ---------------------------
app = FastAPI()

# BASE_DIR points to the current app directory (D:\SCM_C\SCM_C)
BASE_DIR = Path(__file__).resolve().parent

# Static and template directories
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Create if missing (good during dev)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Session middleware (kept for current UI flow)
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------
# MongoDB connection
# ---------------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_collection = db["user"]
logins_collection = db["logins"]
shipment_collection = db["shipments"]
collection = db["sensor_data_collection"]
password_resets = db["password_resets"]

# Ensure unique email index to prevent races/duplicates
try:
    users_collection.create_index("email", unique=True)
except Exception as e:
    logger.warning("Could not create unique index on users_collection.email: %s", e)


# collection = db["device-data"]  # if you switch later

# ==========================================================
# Session & Refresh Token Helpers
# ==========================================================

sessions_collection = db["sessions"]

# Create useful indexes for cleanup & uniqueness
try:
    sessions_collection.create_index("session_id", unique=True)
    sessions_collection.create_index("expires_at", expireAfterSeconds=0)
except Exception as e:
    logger.exception("Could not create indexes on sessions_collection: %s", e)


# Constants
REFRESH_TOKEN_EXPIRE_DAYS = 1  # 1-day refresh lifetime

# -----------------------------
# Utility functions
# -----------------------------
def _random_token() -> str:
    return secrets.token_urlsafe(32)

def _hash_token(token: str) -> str:
    """Return SHA-256 hash for refresh token (so we don't store raw tokens)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

# -----------------------------
# Session creation
# -----------------------------
def create_session_record(email: str, user_agent: Optional[str] = None, ip: Optional[str] = None):
    # Fetch user from DB
    user = users_collection.find_one({"email": email})
    username = user.get("name", "Unknown") if user else "Unknown"

    session_id = str(uuid.uuid4())
    refresh_token_raw = _random_token()
    refresh_token_hash = _hash_token(refresh_token_raw)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    session_doc = {
        "session_id": session_id,
        "email": email,
        "username": username,     # <-- FIXED (now defined)
        "refresh_token_hash": refresh_token_hash,
        "created_at": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "user_agent": user_agent,
        "ip": ip,
        "expires_at": expires_at,
        "revoked": False,
    }

    sessions_collection.insert_one(session_doc)
    return {
        "session_id": session_id,
        "refresh_token": refresh_token_raw,
        "expires_at": expires_at,
    }

# -----------------------------
# Session lookup & revocation
# -----------------------------
def revoke_session(session_id: str):
    """Marks a session as revoked."""
    sessions_collection.update_one(
        {"session_id": session_id},
        {"$set": {"revoked": True, "revoked_at": datetime.utcnow()}},
    )

def get_session_by_id(session_id: str):
    """Fetches a session by ID."""
    return sessions_collection.find_one({"session_id": session_id})


# ==========================================================
# JWT Helper Functions
# ==========================================================

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10"))
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def create_access_token(data: dict, session_id: Optional[str] = None, expires_minutes: Optional[int] = None) -> str:
    """
    Create a signed JWT for the authenticated user.
    Optionally binds the token to a session_id.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    # Attach session info
    if session_id:
        to_encode.update({"sid": session_id})

    # Unique token identifier (for tracing or logout)
    to_encode.update({"jti": str(uuid.uuid4())})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    """
    Verify and decode a JWT.
    Returns payload if valid, None if invalid/expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def is_token_revoked(payload: dict) -> bool:
    """
    Checks whether a session is revoked or expired.
    Returns True if invalid/revoked.
    """
    sid = payload.get("sid")
    if not sid:
        return True  # tokens without session id not trusted

    sess = get_session_by_id(sid)
    if not sess:
        return True
    if sess.get("revoked"):
        return True
    if sess.get("expires_at") and sess["expires_at"] < datetime.utcnow():
        return True

    # Update last_seen timestamp
    sessions_collection.update_one(
        {"session_id": sid},
        {"$set": {"last_seen": datetime.utcnow()}}
    )
    return False
# ==========================================================
# MFA Initialization (after helpers)
# ==========================================================
mfa_init(
    templates,
    users_collection,
    logins_collection,
    create_session_record_func=create_session_record,
    create_access_token_func=create_access_token
)
app.include_router(mfa_router)


# ---------------------------
# JWT helpers
# ---------------------------
def create_access_token(data: dict, session_id: Optional[str] = None, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES if expires_minutes is None else expires_minutes)
    to_encode.update({"exp": expire})
    
    if session_id:
        to_encode.update({"sid": session_id})

    to_encode.update({"jti": str(uuid.uuid4())})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None  # invalid or expired
    
def create_access_token(data: dict, session_id: Optional[str] = None, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES if expires_minutes is None else expires_minutes)
    to_encode.update({"exp": expire})
    # add session id and jti
    if session_id:
        to_encode.update({"sid": session_id})
    to_encode.update({"jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def is_token_revoked(payload: dict) -> bool:
    # payload is the decoded JWT
    sid = payload.get("sid")
    if not sid:
        # tokens without session id are considered invalid for our flow
        return True
    sess = get_session_by_id(sid)
    if not sess:
        return True
    if sess.get("revoked"):
        return True
    # optional: check refresh expiry? session document has expires_at
    if sess.get("expires_at") and sess["expires_at"] < datetime.utcnow():
        return True
    # update last_seen
    sessions_collection.update_one({"session_id": sid}, {"$set": {"last_seen": datetime.utcnow()}})
    return False
    
@app.post("/token/refresh")
def refresh_token_endpoint(request: Request, refresh_token: str = Form(...)):
    """
    Accepts refresh_token (raw string). Returns new access_token.
    Refresh token is valid for 1 day (session.expires_at).
    """
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh token")

    refresh_hash = _hash_token(refresh_token)
    sess = sessions_collection.find_one({"refresh_token_hash": refresh_hash})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if sess.get("revoked"):
        raise HTTPException(status_code=401, detail="Session revoked")

    if sess.get("expires_at") and sess["expires_at"] < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # OK → issue new access token
    email = sess["email"]
    user = users_collection.find_one({"email": email})
    access_token = create_access_token(
        {"sub": email, "role": user.get("role", "user")},
        session_id=sess["session_id"]
    )

    sessions_collection.update_one(
        {"session_id": sess["session_id"]},
        {"$set": {"last_seen": datetime.utcnow()}}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES
    }

    #-----------------------------
    #  Session & Refresh token helpers 
    #-----------------------------


REFRESH_TOKEN_EXPIRE_DAYS = 1  # user asked: 1 day

def _random_token() -> str:
    return secrets.token_urlsafe(32)

def _hash_token(token: str) -> str:
    # store hashed refresh token in DB so raw token not stored in cleartext
    # using sha256 (not password hashing) — you may choose bcrypt if you want slower hashing
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_session_record(email: str, user_agent: Optional[str] = None, ip: Optional[str] = None):
    session_id = str(uuid.uuid4())
    refresh_token_raw = _random_token()
    refresh_token_hash = _hash_token(refresh_token_raw)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    session_doc = {
        "session_id": session_id,
        "email": email,
        "refresh_token_hash": refresh_token_hash,
        "created_at": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "user_agent": user_agent,
        "ip": ip,
        "expires_at": expires_at,
        "revoked": False,
    }
    sessions_collection.insert_one(session_doc)
    return {"session_id": session_id, "refresh_token": refresh_token_raw, "expires_at": expires_at}

def revoke_session(session_id: str):
    sessions_collection.update_one({"session_id": session_id}, {"$set": {"revoked": True, "revoked_at": datetime.utcnow()}})

def get_session_by_id(session_id: str):
    return sessions_collection.find_one({"session_id": session_id})


# ---------------------------
# Dependencies
# ---------------------------
async def get_current_user_from_token(request: Request):
    authorization: str = request.headers.get("Authorization")
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token:
        token = request.session.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_access_token(token)
    if payload is None:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    # check session revocation
    if is_token_revoked(payload):
        # clear session and force login
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired.")
    email = payload.get("sub")
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_current_admin_user(current_user: dict = Depends(get_current_user_from_token)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have enough privileges",
        )
    return current_user

# ---------------------------
# Global Error Handlers
# ---------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # For HTML responses, redirect to login with a flash message
    if request.headers.get("accept", "").startswith("text/html"):
        request.session["flash"] = exc.detail
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse({"detail": exc.errors()}, status_code=400)

# ---------------------------
# Logging
# ---------------------------
logger = logging.getLogger("app")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(str(BASE_DIR / "app.log"))
stream_handler = logging.StreamHandler()

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# ---------------------------
# OAuth2 (only used by Swagger locks)
# ---------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ---------------------------
# Routes
# ---------------------------
@app.get("/", response_class=HTMLResponse)
def root():
    logger.info("Root endpoint accessed")
    return RedirectResponse(url="/login")

# ===============================
# LOGIN ROUTES (FINAL – NO DUPLICATES)
# ===============================

@app.get("/login", response_class=HTMLResponse)
def get_login(request: Request):
    logger.info("Login endpoint accessed")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash},
    )


@app.post("/login")
async def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response"),
):
    logger.info("Login form submitted")

    # ------------------------------------------
    # 1️⃣ VERIFY RECAPTCHA
    # ------------------------------------------
    if not DEV_SKIP_RECAPTCHA:
        try:
            r = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response},
                timeout=10,
            )
            if not r.json().get("success"):
                request.session["flash"] = "reCAPTCHA failed."
                return RedirectResponse("/login", status_code=302)
        except Exception:
            request.session["flash"] = "reCAPTCHA check failed."
            return RedirectResponse("/login", status_code=302)

    # ------------------------------------------
    # 2️⃣ CHECK USER IN DATABASE
    # ------------------------------------------
    user = users_collection.find_one({"email": username})
    if not user or not pwd_context.verify(password, user["password_hash"]):
        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.utcnow(),
            "status": "failed"
        })
        request.session["flash"] = "Invalid credentials."
        return RedirectResponse("/login", status_code=302)

    role = user.get("role", "user")

    # ------------------------------------------
    # 3️⃣ ADMIN → BYPASS MFA
    # ------------------------------------------
    if role == "admin":
        session_info = create_session_record(user["email"])
        access_token = create_access_token(
            {"sub": user["email"], "role": role},
            session_id=session_info["session_id"]
        )

        # store in session
        request.session["access_token"] = access_token
        request.session["username"] = user["email"]
        request.session["role"] = role
        request.session["session_id"] = session_info["session_id"]

        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.utcnow(),
            "status": "success"
        })

        return RedirectResponse("/admin-dashboard", status_code=302)

    # ------------------------------------------
    # 4️⃣ NORMAL USER → MFA CHECK
    # ------------------------------------------
    mfa_info = user.get("mfa", {})

    if mfa_info.get("enabled"):
        request.session["pending_mfa_email"] = user["email"]
        request.session["pending_mfa_role"] = role
        request.session["pending_mfa_name"] = user.get("name", "")
        request.session["flash"] = "Enter your MFA code."
        return RedirectResponse("/mfa/relogin", status_code=302)

    # ------------------------------------------
    # 5️⃣ FIRST TIME USER → MFA SETUP
    # ------------------------------------------
    request.session["mfa_temp_user"] = user["email"]
    return RedirectResponse("/mfa/setup", status_code=302)


# >>> SIGNUP ROUTES (needed for login.html link)
@app.get("/signup", response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("signup.html", {"request": request, "flash": flash})

@app.post("/signup")
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form("user"),
):
        # 0. Real domain email validation
    if not is_real_domain_email(email):
        request.session["flash"] = "Invalid email domain. Enter a real email provider (Gmail, Outlook, Yahoo, company domain)."
        return RedirectResponse("/signup", status_code=302)

    # 1. Password check
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse("/signup", status_code=302)

    # 2. Email exists check
    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        return RedirectResponse("/signup", status_code=302)

    # 3. Set role
    if role not in ["user", "admin"]:
        role = "user"

    # 4. Create verification token
    token = secrets.token_urlsafe(32)
    verification_expires_at = datetime.utcnow() + timedelta(hours=24)

    password_hash = pwd_context.hash(password)

    # 5. Insert into DB
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": password_hash,
        "role": role,
        "created_at": datetime.utcnow(),
        "email_verified": False,
        "verification_token": token,
        "verification_expires_at": verification_expires_at,
    })

    # 6. Send verification email
    verification_link = f"http://127.0.0.1:8000/verify-email?token={token}"

    email_body = f"""
Hello {fullname},

Please verify your email by visiting the link below (valid for 24 hours):
{verification_link}

If you did not sign up, ignore this message.
"""

    try:
        send_email(email, "Verify your SCMLite email", email_body)
    except Exception as e:
        logger.exception("send_email failed: %s", e)

    # 7. Flash + redirect
    request.session["flash"] = "Account created. Check your email for verification."
    return RedirectResponse("/login", status_code=302)

# >>> EMAIL VERIFICATION ROUTE

@app.get("/verify-email")
def get_verify_email(request: Request, token: str = None):
    if not token:
        request.session["flash"] = "Missing verification token."
        return RedirectResponse("/login", status_code=302)

    user = users_collection.find_one({"verification_token": token})
    if not user:
        request.session["flash"] = "Invalid verification link."
        return RedirectResponse("/login", status_code=302)

    if user.get("email_verified"):
        request.session["flash"] = "Email already verified."
        return RedirectResponse("/login", status_code=302)

    if user.get("verification_expires_at") and user["verification_expires_at"] < datetime.utcnow():
        request.session["flash"] = "Verification link expired. Request a new one."
        return RedirectResponse(f"/resend-verification?email={user['email']}", status_code=302)

    users_collection.update_one(
        {"email": user["email"]},
        {"$set": {"email_verified": True}, "$unset": {"verification_token": "", "verification_expires_at": ""}}
    )

    request.session["flash"] = "Email verified successfully. Please log in."
    return RedirectResponse("/login", status_code=302)


#resend-verification
@app.post("/resend-verification")
def post_resend_verification(request: Request, email: str = Form(...)):
    user = users_collection.find_one({"email": email})
    if not user:
        request.session["flash"] = "Email not registered."
        return RedirectResponse("/login", status_code=302)
    if user.get("email_verified"):
        request.session["flash"] = "Email already verified."
        return RedirectResponse("/login", status_code=302)

    new_token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=24)
    users_collection.update_one({"email": email}, {"$set": {"verification_token": new_token, "verification_expires_at": expires}})

    verification_link = f"http://127.0.0.1:8000/verify-email?token={new_token}"
    send_email(email, "Verify your email - SCMLite", f"Click here to verify: {verification_link}")

    request.session["flash"] = "Verification email sent (check spam)."
    return RedirectResponse("/login", status_code=302)

@app.get("/forgot-password", response_class=HTMLResponse)
def get_forgot_password(request: Request):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("forgot_password.html", {"request": request, "flash": flash})


@app.get("/reset-password", response_class=HTMLResponse)
def get_reset_password(request: Request, token: str):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "token": token, "flash": flash}
    )

@app.post("/reset-password")
def reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    record = password_resets.find_one({"token": token})

    # Validate token
    if not record or record["expires_at"] < datetime.utcnow():
        request.session["flash"] = "Invalid or expired reset link."
        return RedirectResponse("/login", status_code=302)

    # Validate passwords
    if new_password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse(f"/reset-password?token={token}", status_code=302)

    # Hash and update password
    password_hash = pwd_context.hash(new_password)
    users_collection.update_one(
        {"email": record["email"]},
        {"$set": {"password_hash": password_hash}}
    )

    # Delete reset token so it can't be reused
    password_resets.delete_one({"token": token})

    # Redirect to login with success message
    request.session["flash"] = "Password reset successful. Please log in."
    return RedirectResponse("/login", status_code=302)

@app.post("/forgot-password")
def post_forgot_password(request: Request, email: str = Form(...)):
    user = users_collection.find_one({"email": email})

    if not user:
        request.session["flash"] = "Email not registered."
        return RedirectResponse("/forgot-password", status_code=302)

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=20)

    password_resets.insert_one({
        "email": email,
        "token": token,
        "expires_at": expires_at
    })

    reset_link = f"http://127.0.0.1:8000/reset-password?token={token}"

    send_email(
        email,
        "Reset your SCMLite password",
        f"Click the link to reset your password:\n\n{reset_link}"
    )

    request.session["flash"] = "Password reset link sent to your email."
    return RedirectResponse("/forgot-password", status_code=302)


# >>> MFA ADDITION: finalize endpoint after MFA success

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f"Dashboard endpoint accessed by {current_user.get('email')}")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "name": current_user.get("name"),
            "role": current_user.get("role")      # <-- IMPORTANT
        }
    )

@app.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"Admin dashboard endpoint accessed by {current_user.get('email')}")
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "name": current_user.get("name"),
            "role": current_user.get("role")      # <-- IMPORTANT
        }
    )


@app.get("/create-shipment", response_class=HTMLResponse)
def get_create_shipment(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f"Create shipment endpoint accessed by {current_user.get('email')}")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "create_shipment.html",
        {"request": request, "user_name": current_user.get("name"), "flash": flash},
    )

@app.post("/create-shipment", response_class=HTMLResponse)
async def create_shipment(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
    shipment_id: str = Form(...),
    po_number: str = Form(...),
    route_details: str = Form(...),
    device: str = Form(...),
    ndc_number: str = Form(...),
    serial_number: str = Form(...),
    container_number: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    origin: str = Form(...),
    destination: str = Form(...),
    status: str = Form(...),
    shipment_description: str = Form(...),
):
    logger.info(f"Shipment creation form submitted by {current_user.get('email')}")
    shipment = {
        "shipment_id": shipment_id,
        "po_number": po_number,
        "route_details": route_details,
        "device": device,
        "ndc_number": ndc_number,
        "serial_number": serial_number,
        "container_number": container_number,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "origin": origin,
        "destination": destination,
        "status": status,
        "shipment_description": shipment_description,
        "created_at": datetime.utcnow(),
    }

    try:
        shipment_collection.insert_one(shipment)
        flash_message = f"Shipment {shipment_id} created successfully!"
        logger.info(f"Shipment {shipment_id} created by {current_user.get('email')}")
    except Exception as e:
        print(f"Database error: {e}")
        flash_message = f"Error creating shipment: {str(e)}"
        logger.error(f"Error creating shipment by {current_user.get('email')}: {e}")

    return templates.TemplateResponse(
        "create_shipment.html", {"request": request, "flash": flash_message}
    )

@app.get("/user_management", response_class=HTMLResponse)
def user_management(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"User management endpoint accessed by {current_user.get('email')}")
    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1, "role": 1}))
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users})

@app.get("/revoke_session/{session_id}")
def revoke_session_admin(session_id: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    result = sessions_collection.update_one(
        {"session_id": session_id},
        {"$set": {"revoked": True}}
    )

    if result.modified_count > 0:
        request.session["flash"] = "Session revoked successfully."
    else:
        request.session["flash"] = "Session not found."

    return RedirectResponse("/active_sessions", status_code=302)

@app.get("/active_sessions", response_class=HTMLResponse)
def get_active_sessions(request: Request, current_user: dict = Depends(get_current_admin_user)):
    sessions = list(sessions_collection.find({}, {"_id": 0}))
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "active_sessions.html",
        {"request": request, "sessions": sessions, "flash": flash}
    )



@app.get("/edit_user/{email}", response_class=HTMLResponse)
async def edit_user(email: str, request: Request):
    user = users_collection.find_one({"email": email})
    if not user:
        return HTMLResponse("User not found", status_code=404)
    return templates.TemplateResponse("edit_users.html", {"request": request, "user": user})

@app.get("/edit-users/{email}", response_class=HTMLResponse)
async def get_edit_user(request: Request, email: str, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"Edit user endpoint accessed for {email} by {current_user.get('email')}")
    user = users_collection.find_one({"email": email})
    flash = request.session.pop("flash", None)

    if not user:
        request.session["flash"] = "User not found."
        logger.warning(f"User {email} not found for editing by {current_user.get('email')}")
        return RedirectResponse(url="/user_management", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("edit_user.html", {"request": request, "user": user, "flash": flash})

@app.post("/update-user")
async def update_user(
    request: Request,
    old_email: str = Form(...),
    name: str = Form(...),
    new_email: str = Form(...),
    role: str = Form(...),
    current_user: dict = Depends(get_current_admin_user),
):
    logger.info(f"Update user form submitted for {old_email} by {current_user.get('email')}")

    # Fetch existing user BEFORE updating
    old_user = users_collection.find_one({"email": old_email})
    if not old_user:
        request.session["flash"] = "User not found."
        return RedirectResponse("/user_management", status_code=302)

    result = users_collection.update_one(
        {"email": old_email},
        {"$set": {"name": name, "email": new_email, "role": role}}
    )

    if result.modified_count == 1:
        request.session["flash"] = "User updated successfully."

        try:
            subject = "Your SCMLite Account Was Updated"
            body = f"""
Hello {name},

Your SCMLite account has been updated by an administrator.

Previous Email: {old_email}
New Email: {new_email}

Previous Name: {old_user.get("name")}
Updated Name: {name}

Previous Role: {old_user.get("role")}
Updated Role: {role}

Updated By: {current_user.get('email')}
Date (UTC): {datetime.utcnow()}
"""

            send_email(new_email, subject, body)

        except Exception as e:
            logger.exception(f"Failed to send update notification email to {new_email}: {e}")

    else:
        request.session["flash"] = "No changes made or user not found."

    return RedirectResponse("/user_management", status_code=302)

@app.get("/assign-admin/{email}")
def assign_admin(email: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"Assign admin endpoint accessed for {email} by {current_user.get('email')}")

    user = users_collection.find_one({"email": email})
    if not user:
        request.session["flash"] = "User not found."
        logger.warning(f"User {email} not found for admin assignment by {current_user.get('email')}")
        return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

    # If already admin
    if user.get("role") == "admin":
        request.session["flash"] = "User is already an admin."
        return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

    # Update role to admin
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"role": "admin"}}
    )

    if result.modified_count == 1:
        logger.info(f"{email} promoted to ADMIN by {current_user.get('email')}")
        request.session["flash"] = f"{email} is now an admin."

        # ===============================
        # SEND EMAIL NOTIFICATION
        # ===============================
        try:
            subject = "Your SCMLite Role Has Been Updated"
            body = f"""
Hello {user.get('name', '')},

This is to inform you that your role has been updated to ADMIN in the SCMLite system.

Updated By: {current_user.get('email')}
Date & Time: {datetime.utcnow()} UTC

You now have access to admin features such as:
- User Management
- Shipment Management
- Session Monitoring

If this was not intended, contact your system administrator immediately.

Thank you,
SCMLite Security System
"""

            send_email(email, subject, body)

        except Exception as e:
            logger.exception(f"Email notification failed for {email}: {e}")

    else:
        request.session["flash"] = "No changes made."
        logger.warning(f"No changes made while assigning admin to {email}")

    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

@app.get("/edit-shipment", response_class=HTMLResponse)
def get_edit_shipment(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"Edit shipment endpoint accessed by {current_user.get('email')}")
    flash = request.session.pop("flash", None)
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse(
        "edit_shipment.html",
        {"request": request, "shipments": shipments, "flash": flash},
    )

@app.post("/edit-shipment")
def post_edit_shipment(
    request: Request,
    current_user: dict = Depends(get_current_admin_user),
    shipment_id: str = Form(...),
    status_update: str = Form(..., alias="status"),
    destination: str = Form(...),
    expected_delivery_date: str = Form(...),
):
    logger.info(f"Edit shipment form submitted for {shipment_id} by {current_user.get('email')}")
    result = shipment_collection.update_one(
        {"shipment_id": shipment_id},
        {
            "$set": {
                "status": status_update,
                "destination": destination,
                "expected_delivery_date": expected_delivery_date,
                "last_updated": datetime.utcnow(),
            }
        },
    )
    if result.modified_count > 0:
        request.session["flash"] = "Shipment updated successfully."
        logger.info(f"Shipment {shipment_id} updated by {current_user.get('email')}")
    else:
        request.session["flash"] = "No changes made or shipment not found."
        logger.warning(f"No changes made or shipment {shipment_id} not found during update by {current_user.get('email')}")
    return RedirectResponse(url="/edit-shipment", status_code=status.HTTP_302_FOUND)

@app.get("/delete-shipment/{shipment_id}")
def delete_shipment(shipment_id: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f"Delete shipment endpoint accessed for {shipment_id} by {current_user.get('email')}")
    result = shipment_collection.delete_one({"shipment_id": shipment_id})
    if result.deleted_count > 0:
        request.session["flash"] = "Shipment deleted successfully."
        logger.info(f"Shipment {shipment_id} deleted by {current_user.get('email')}")
    else:
        request.session["flash"] = "Shipment not found or already deleted."
        logger.warning(f"Shipment {shipment_id} not found or already deleted during deletion by {current_user.get('email')}")
    return RedirectResponse(url="/edit-shipment", status_code=status.HTTP_302_FOUND)

@app.get("/all-shipments", response_class=HTMLResponse)
def get_all_shipments(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f"All shipments endpoint accessed by {current_user.get('email')}")
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse(
        "all_shipments.html", {"request": request, "shipments": shipments, "role": current_user.get("role")}
    )

@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f"Account page accessed by {current_user.get('email')}")
    return templates.TemplateResponse("account.html", {"request": request, "user": current_user})

@app.get("/device-data", response_class=HTMLResponse)
async def device_data(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f"Device data endpoint accessed by {current_user.get('email')}")
    data = list(collection.find().sort([("_id", -1)]).limit(10))
    for item in data:
        item["_id"] = str(item["_id"])
    return templates.TemplateResponse("device_data.html", {"request": request, "devices": data})



# ===============================
# LOGIN ROUTES (Updated for MFA)
# ===============================


@app.get("/logout")
def logout(request: Request):
    logger.info("Logout endpoint accessed")

    # Try to get session_id from JWT
    sid = None
    token = request.session.get("access_token")
    if token:
        payload = decode_access_token(token)
        if payload and payload.get("sid"):
            sid = payload.get("sid")

    # Fallback to session cookie
    if not sid:
        sid = request.session.get("session_id") or request.session.get("session_id_cookie")

    # Revoke server-side session if exists
    if sid:
        try:
            revoke_session(sid)
            logger.info(f"Session {sid} revoked successfully")
        except Exception:
            logger.exception(f"Failed to revoke session {sid}")

    # Clear client session
    request.session.clear()
    request.session["flash"] = "Logged out successfully."

    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# -----------------------------
# LOGOUT ROUTE
# -----------------------------
# @app.get("/login", response_class=HTMLResponse)
# def get_login(request: Request):
#     flash = request.session.pop("flash", None)
#     return templates.TemplateResponse(
#         "login.html",
#         {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash},
#     )

# @app.post("/login")
# def post_login(
#     request: Request,
#     username: str = Form(...),
#     password: str = Form(...),
#     g_recaptcha_response: str = Form(alias="g-recaptcha-response"),
# ):
#     # ──────────────────────────────────────────────
#     # 1️⃣ Verify reCAPTCHA (optional dev skip)
#     # ──────────────────────────────────────────────
#     recaptcha_ok = True if DEV_SKIP_RECAPTCHA else False
#     if not DEV_SKIP_RECAPTCHA:
#         try:
#             r = requests.post(
#                 "https://www.google.com/recaptcha/api/siteverify",
#                 data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response},
#                 timeout=10,
#             )
#             recaptcha_ok = bool(r.json().get("success"))
#         except Exception:
#             logger.exception("reCAPTCHA verification failed (network/parse error).")
#             recaptcha_ok = False

#     if not recaptcha_ok:
#         request.session["flash"] = "reCAPTCHA failed."
#         return RedirectResponse("/login", status_code=302)

#     # ──────────────────────────────────────────────
#     # 2️⃣ Validate user credentials
#     # ──────────────────────────────────────────────
#     user = users_collection.find_one({"email": username})
#     if not user or not pwd_context.verify(password, user["password_hash"]):
#         logins_collection.insert_one(
#             {"email": username, "login_time": datetime.utcnow(), "status": "failed"}
#         )
#         request.session["flash"] = "Invalid credentials."
#         return RedirectResponse("/login", status_code=302)

#     # ──────────────────────────────────────────────
#     # 3️⃣ Check if user has MFA enabled
#     # ──────────────────────────────────────────────
#     mfa_info = user.get("mfa", {})
#     if mfa_info.get("enabled"):
#         # Store temporarily to verify MFA next
#         request.session["pending_mfa_email"] = user["email"]
#         request.session["pending_mfa_role"] = user.get("role", "user")
#         request.session["pending_mfa_name"] = user.get("name", "")
#         request.session["flash"] = "Enter your MFA code from the Authenticator app."
#         return RedirectResponse("/mfa/verify", status_code=302)

#     # ──────────────────────────────────────────────
#     # 4️⃣ If MFA not enabled, log in directly
#     # ──────────────────────────────────────────────
#     token = create_access_token({"sub": user["email"]})
#     request.session["access_token"] = token
#     request.session["user"] = {
#         "email": user["email"],
#         "role": user.get("role", "user"),
#         "name": user.get("name"),
#     }

#     logins_collection.insert_one(
#         {"email": username, "login_time": datetime.utcnow(), "status": "success"}
#     )
#     return RedirectResponse("/dashboard", status_code=302)



# ---------------------------
# Custom OpenAPI (lock icons)
# ---------------------------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Your API",
        version="1.0.0",
        description="API with OAuth2 Bearer and Swagger UI lock icon",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }

    # Public paths
    unsecured_paths = [
        "/login", "/signup", "/logout", "/",
        # MFA public endpoints
        "/mfa/setup", "/mfa/verify", "/mfa/enable",
        "/mfa/finish", "/mfa/qrcode.png", "/mfa/finalize"
    ]

    for path, methods in openapi_schema.get("paths", {}).items():
        for method in methods.values():
            if path not in unsecured_paths:
                method["security"] = [{"BearerAuth": []}]
            else:
                method["security"] = []

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/logout")
def logout(request: Request):
    logger.info("Logout endpoint accessed")
    request.session.clear()  # Clear all session data, including JWT in session
    request.session["flash"] = "Logged out successfully."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
