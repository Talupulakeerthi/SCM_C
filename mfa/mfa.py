# mfa.py
import os
import smtplib
import secrets
import hashlib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from fastapi import HTTPException
from pymongo.collection import Collection

# Load environment variables
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM", "SCM Lite <no-reply@example.com>")

OTP_EXP_MIN = int(os.getenv("OTP_EXP_MIN", "5"))        # minutes until OTP expires
OTP_RESEND_COOLDOWN = int(os.getenv("OTP_RESEND_COOLDOWN", "60"))  # seconds cooldown

# ──────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────
def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _generate_code(n_digits: int = 6) -> str:
    return f"{secrets.randbelow(10**n_digits):0{n_digits}}"

def _send_email_otp(to_email: str, code: str):
    subject = "Your SCM Lite OTP Code"
    body = f"""Hi,

Your one-time password (OTP) is: {code}
This code expires in {OTP_EXP_MIN} minute(s).

If you did not try to sign in, you can ignore this email.

— SCM Lite
"""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, [to_email], msg.as_string())

# ──────────────────────────────────────────────
# Public MFA functions
# ──────────────────────────────────────────────
def create_and_send_otp(email: str, mfa_collection: Collection):
    now = datetime.utcnow()
    existing = mfa_collection.find_one({"email": email})
    if existing and existing.get("last_sent_at"):
        delta = (now - existing["last_sent_at"]).total_seconds()
        if delta < OTP_RESEND_COOLDOWN:
            remaining = int(OTP_RESEND_COOLDOWN - delta)
            raise HTTPException(status_code=429,
                detail=f"Please wait {remaining}s before requesting a new OTP.")

    code = _generate_code(6)
    code_hash = _hash_code(code)
    expires_at = now + timedelta(minutes=OTP_EXP_MIN)

    mfa_collection.update_one(
        {"email": email},
        {
            "$set": {
                "code_hash": code_hash,
                "expires_at": expires_at,
                "last_sent_at": now,
                "attempts": 0
            }
        },
        upsert=True
    )

    _send_email_otp(email, code)

def verify_otp(email: str, code_plain: str, mfa_collection: Collection, max_attempts: int = 5) -> bool:
    rec = mfa_collection.find_one({"email": email})
    if not rec:
        return False

    if rec.get("attempts", 0) >= max_attempts:
        return False

    if rec.get("expires_at") and datetime.utcnow() > rec["expires_at"]:
        return False

    ok = _hash_code(code_plain) == rec.get("code_hash")
    if ok:
        mfa_collection.delete_one({"email": email})
    else:
        mfa_collection.update_one({"email": email}, {"$inc": {"attempts": 1}})
    return ok

def can_resend(email: str, mfa_collection: Collection) -> bool:
    rec = mfa_collection.find_one({"email": email})
    if not rec or not rec.get("last_sent_at"):
        return True
    return (datetime.utcnow() - rec["last_sent_at"]).total_seconds() >= OTP_RESEND_COOLDOWN

def resend_otp(email: str, mfa_collection: Collection):
    if not can_resend(email, mfa_collection):
        return False
    create_and_send_otp(email, mfa_collection)
    return True
