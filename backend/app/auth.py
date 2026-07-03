"""JWT authentication + role-based access control."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from .config import settings
from .schemas import Token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)


def _hash(password: str) -> bytes:
    # bcrypt caps input at 72 bytes; truncate defensively.
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt())


def _verify(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed)
    except Exception:
        return False


# In-memory demo user store. Swap for a real DB in production.
USERS: dict[str, dict] = {
    "admin": {"password_hash": _hash("admin"), "role": "admin"},
    "viewer": {"password_hash": _hash("viewer"), "role": "viewer"},
}


def authenticate(username: str, password: str) -> dict | None:
    user = USERS.get(username.lower())
    if not user or not _verify(password, user["password_hash"]):
        return None
    return {"username": username.lower(), "role": user["role"]}


def create_token(username: str, role: str) -> Token:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": username, "role": role, "exp": expire}
    encoded = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return Token(access_token=encoded, role=role)


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> dict:
    creds_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise creds_error
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        username = payload.get("sub")
        role = payload.get("role", "viewer")
        if not username:
            raise creds_error
    except JWTError:
        raise creds_error
    return {"username": username, "role": role}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
