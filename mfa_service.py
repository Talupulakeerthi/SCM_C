# main/mfa_service.py
import pyotp
from io import BytesIO
import qrcode

ISSUER_NAME = "SCMLite"

def new_secret() -> str:
    return pyotp.random_base32()

def provisioning_uri(email: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)

def verify_code(secret: str, code: str, window: int = 1) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=window)

def qr_png(otpauth_uri: str) -> bytes:
    img = qrcode.make(otpauth_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()



