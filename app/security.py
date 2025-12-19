import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, logger
from .database import sessions_collection, users_collection

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
REFRESH_TOKEN_EXPIRE_DAYS = 1

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_session_record(email: str, user_agent: Optional[str] = None, ip: Optional[str] = None):
    user = users_collection.find_one({"email": email})
    username = user.get("name", "Unknown") if user else "Unknown"
    session_id = str(uuid.uuid4())
    refresh_token_raw = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    session_doc = {
        "session_id": session_id,
        "email": email,
        "username": username,
        "refresh_token_hash": _hash_token(refresh_token_raw),
        "created_at": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "user_agent": user_agent,
        "ip": ip,
        "expires_at": expires_at,
        "revoked": False,
    }
    sessions_collection.insert_one(session_doc)
    return {"session_id": session_id, "refresh_token": refresh_token_raw, "expires_at": expires_at}

def create_access_token(data: dict, session_id: Optional[str] = None, expires_minutes: Optional[int] = None) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=(expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES))
    payload.update({"exp": expire, "jti": str(uuid.uuid4())})
    if session_id: payload["sid"] = session_id
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def is_token_revoked(payload: dict) -> bool:
    if not payload or "sid" not in payload: return True
    sess = sessions_collection.find_one({"session_id": payload["sid"]})
    if not sess or sess.get("revoked") or (sess.get("expires_at") and sess["expires_at"] < datetime.utcnow()):
        return True
    sessions_collection.update_one({"session_id": payload["sid"]}, {"$set": {"last_seen": datetime.utcnow()}})
    return False

def revoke_session(session_id: str):
    sessions_collection.update_one({"session_id": session_id}, {"$set": {"revoked": True, "revoked_at": datetime.utcnow()}})