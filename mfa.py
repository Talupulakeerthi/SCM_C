# mfa.py
import os
import smtplib
import secrets
import hashlib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from fastapi import HTTPException

# Load from env (so mfa.py is self-contained)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM", "SCM Lite <no-reply@example.com>")

OTP_EXP_MIN = int(os.getenv("OTP_EXP_MIN", "5"))
OTP_RESEND_COOLDOWN = int(os.getenv("OTP_RESEND_COOLDOWN", "60"))  # seconds

def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()

def _generate_otp(n_digits: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(n_digits))

def _send_email_otp(to_email: str, otp: str, minutes: int):
    subject = "Your SCM Lite OTP Code"
    body = f"""Hi,

Your one-time password (OTP) is: {otp}
This code expires in {minutes} minute(s).

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

def create_and_send_otp(email: str, mfa_collection):
    """Upsert OTP record, enforce resend cooldown, and send email."""
    now = datetime.utcnow()

    existing = mfa_collection.find_one({"email": email})
    if existing and existing.get("last_sent"):
        delta = (now - existing["last_sent"]).total_seconds()
        if delta < OTP_RESEND_COOLDOWN:
            remaining = int(OTP_RESEND_COOLDOWN - delta)
            raise HTTPException(status_code=429,
                detail=f"Please wait {remaining}s before requesting a new OTP.")

    otp = _generate_otp(6)
    otp_hash = _hash_otp(otp)
    expires_at = now + timedelta(minutes=OTP_EXP_MIN)

    mfa_collection.update_one(
        {"email": email},
        {
            "$set": {
                "otp_hash": otp_hash,
                "expires_at": expires_at,
                "last_sent": now,
                "attempts": 0,
            }
        },
        upsert=True
    )

    _send_email_otp(email, otp, OTP_EXP_MIN)

def verify_otp(email: str, otp_plain: str, mfa_collection, max_attempts: int = 5) -> bool:
    """Return True if OTP is correct & valid, and delete the record on success."""
    rec = mfa_collection.find_one({"email": email})
    if not rec:
        return False

    attempts = int(rec.get("attempts", 0))
    if attempts >= max_attempts:
        return False

    exp = rec.get("expires_at")
    if exp and datetime.utcnow() > exp:
        return False

    ok = _hash_otp(otp_plain) == rec.get("otp_hash")
    if ok:
        mfa_collection.delete_one({"email": email})
    else:
        mfa_collection.update_one({"email": email}, {"$inc": {"attempts": 1}})
    return ok
