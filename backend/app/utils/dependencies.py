import hashlib
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.database import get_db
from app.db.models import Sensor, User
from app.schemas.schemas import TokenData

# If you are using /api/v1 prefix, it MUST be included here
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")
# Same scheme but non-fatal: returns None instead of 401 when no token is present.
# Used by endpoints that behave differently for anonymous vs authenticated callers
# (e.g. registration, which is admin-only unless open registration is enabled).
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)


def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme_optional),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Resolve the caller if a valid token is present, else None (never raises)."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        return None
    if not email:
        return None
    return db.query(User).filter(User.email == email).first()

# 1. This function gets the logged-in user
def _bearer_or_cookie_token(
    request: Request,
    bearer: Optional[str] = Depends(oauth2_scheme_optional),
) -> Optional[str]:
    """Prefer an Authorization: Bearer header, else the httpOnly auth cookie."""
    if bearer:
        return bearer
    return request.cookies.get(settings.AUTH_COOKIE_NAME)


def get_current_user(token: Optional[str] = Depends(_bearer_or_cookie_token), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

# 2. Role-based access control
# Roles in ascending order; require_role(min_role) enforces hierarchical access.
_ROLE_HIERARCHY = {"viewer": 1, "analyst": 2, "admin": 3}


def _user_role_rank(user: User) -> int:
    """Resolve the user's effective role rank.

    Falls back to is_admin for accounts that predate the role column.
    """
    role = getattr(user, "role", None)
    if role and role in _ROLE_HIERARCHY:
        return _ROLE_HIERARCHY[role]
    return _ROLE_HIERARCHY["admin"] if user.is_admin else _ROLE_HIERARCHY["analyst"]


def require_role(min_role: str):
    """Dependency factory: require the user to be at least `min_role`."""
    if min_role not in _ROLE_HIERARCHY:
        raise ValueError(f"Unknown role: {min_role}")
    required = _ROLE_HIERARCHY[min_role]

    def _dep(current_user: User = Depends(get_current_user)) -> User:
        if _user_role_rank(current_user) < required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {min_role} role or higher.",
            )
        return current_user

    return _dep


# Convenience pre-bound dependencies — most route signatures import these
# rather than calling require_role() inline.
get_current_viewer = require_role("viewer")
get_current_analyst = require_role("analyst")
get_current_admin = require_role("admin")


# 3. Sensor authentication via X-Sensor-Key header.
# Sensors don't have user sessions — they're long-running agents with a
# rotated-by-recreation API key. SHA-256 (not bcrypt) for the hash so the
# lookup is fast (could happen 100+ times/sec under load) and deterministic.
def get_current_sensor(
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    db: Session = Depends(get_db),
) -> Sensor:
    if not x_sensor_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Sensor-Key header required",
        )
    key_hash = hashlib.sha256(x_sensor_key.encode("utf-8")).hexdigest()
    sensor = db.query(Sensor).filter(Sensor.api_key_hash == key_hash).first()
    if sensor is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid sensor key",
        )
    return sensor