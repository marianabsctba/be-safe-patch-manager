import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .database import get_db
from .models import AdminSession, AdminUser


ROLE_LEVELS = {"viewer": 10, "operator": 20, "admin": 30}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,128}$")
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def _required_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    if len(value) < 32:
        raise RuntimeError(f"{name} must be at least 32 characters long")
    lowered = value.lower()
    if any(marker in lowered for marker in ("change-me", "changeme", "troque-por", "replace-with", "example", "placeholder")):
        raise RuntimeError(f"{name} still looks like a placeholder")
    return value


def _optional_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        return ""
    if len(value) < 32:
        raise RuntimeError(f"{name} must be at least 32 characters long when configured")
    lowered = value.lower()
    if any(marker in lowered for marker in ("change-me", "changeme", "troque-por", "replace-with", "example", "placeholder")):
        raise RuntimeError(f"{name} still looks like a placeholder")
    return value


def _seconds_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


ENROLLMENT_TOKEN = _required_secret("ENROLLMENT_TOKEN")
BREAK_GLASS_ADMIN_TOKEN = _optional_secret("BREAK_GLASS_ADMIN_TOKEN")
SESSION_TTL_SECONDS = _seconds_setting("AUTH_SESSION_TTL_SECONDS", 28800, 900, 604800)

if BREAK_GLASS_ADMIN_TOKEN and hmac.compare_digest(BREAK_GLASS_ADMIN_TOKEN, ENROLLMENT_TOKEN):
    raise RuntimeError("BREAK_GLASS_ADMIN_TOKEN and ENROLLMENT_TOKEN must be different")


def utcnow():
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def validate_username(username: str) -> str:
    normalized = str(username or "").strip().lower()
    if not USERNAME_RE.fullmatch(normalized):
        raise ValueError("username must use 3-128 characters: letters, numbers, . _ @ -")
    return normalized


def validate_role(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized not in ROLE_LEVELS:
        raise ValueError("role must be viewer, operator or admin")
    return normalized


def validate_password_strength(password: str) -> None:
    if len(password) < 14:
        raise ValueError("password must be at least 14 characters long")
    lowered = password.lower()
    if any(marker in lowered for marker in ("password", "senha123", "changeme", "change-me", "replace-with", "placeholder")):
        raise ValueError("password is too predictable")


def password_hash(password: str) -> str:
    validate_password_strength(password)
    return PASSWORD_HASHER.hash(password)


def password_verify(password_hash_value: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash_value, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash_value: str) -> bool:
    try:
        return PASSWORD_HASHER.check_needs_rehash(password_hash_value)
    except InvalidHashError:
        return True


def create_session(db: Session, user: AdminUser) -> tuple[str, AdminSession]:
    raw_token = new_token()
    session = AdminSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
        last_seen_at=utcnow(),
    )
    db.add(session)
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(session)
    return raw_token, session


def revoke_session(db: Session, raw_token: str) -> bool:
    if not raw_token:
        return False
    session = db.query(AdminSession).filter(AdminSession.token_hash == hash_token(raw_token)).first()
    if not session:
        return False
    db.delete(session)
    db.commit()
    return True


def principal_for_user(user: AdminUser, session: AdminSession | None = None) -> dict:
    return {
        "kind": "user",
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "actor": f"user:{user.username}",
        "session_id": session.id if session else "",
    }


def current_principal(
    x_session_token: str | None = Header(default=None),
    x_break_glass_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if BREAK_GLASS_ADMIN_TOKEN and x_break_glass_token:
        if hmac.compare_digest(x_break_glass_token, BREAK_GLASS_ADMIN_TOKEN):
            return {
                "kind": "break_glass",
                "user_id": "",
                "username": "break-glass",
                "role": "admin",
                "actor": "break-glass",
                "session_id": "",
            }

    if not x_session_token:
        raise HTTPException(status_code=401, detail="missing session token")

    token_hash = hash_token(x_session_token)
    session = db.query(AdminSession).filter(AdminSession.token_hash == token_hash).first()
    if not session:
        raise HTTPException(status_code=401, detail="invalid session")

    instant = utcnow()
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= instant:
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="session expired")

    user = db.get(AdminUser, session.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=403, detail="user is inactive")

    if user.role not in ROLE_LEVELS:
        raise HTTPException(status_code=403, detail="invalid user role")

    last_seen = session.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if (instant - last_seen).total_seconds() >= 60:
        session.last_seen_at = instant
        db.commit()

    return principal_for_user(user, session)


def _require_level(minimum_role: str, principal: dict) -> dict:
    actual = ROLE_LEVELS.get(principal.get("role", ""), 0)
    required = ROLE_LEVELS[minimum_role]
    if actual < required:
        raise HTTPException(status_code=403, detail=f"{minimum_role} role required")
    return principal


def require_viewer(principal: dict = Depends(current_principal)):
    return _require_level("viewer", principal)


def require_operator(principal: dict = Depends(current_principal)):
    return _require_level("operator", principal)


def require_admin(principal: dict = Depends(current_principal)):
    return _require_level("admin", principal)


def require_enrollment(x_enrollment_token: str | None = Header(default=None)):
    if not x_enrollment_token or not hmac.compare_digest(x_enrollment_token, ENROLLMENT_TOKEN):
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    return True
