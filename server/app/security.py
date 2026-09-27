import hashlib
import hmac
import os
import secrets
from fastapi import Header, HTTPException


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


ADMIN_TOKEN = _required_secret("ADMIN_TOKEN")
ENROLLMENT_TOKEN = _required_secret("ENROLLMENT_TOKEN")

if hmac.compare_digest(ADMIN_TOKEN, ENROLLMENT_TOKEN):
    raise RuntimeError("ADMIN_TOKEN and ENROLLMENT_TOKEN must be different")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def require_admin(x_admin_token: str | None = Header(default=None)):
    if not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid admin token")
    return True


def require_enrollment(x_enrollment_token: str | None = Header(default=None)):
    if not x_enrollment_token or not hmac.compare_digest(x_enrollment_token, ENROLLMENT_TOKEN):
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    return True
