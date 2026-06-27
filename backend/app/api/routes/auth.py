from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User
from app.core.config import settings
from app.core.rate_limiter import limiter
from app.core.security import hash_password, verify_password, create_access_token
from app.schemas.schemas import UserCreate, UserOut, Token
from app.utils.dependencies import get_optional_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _is_admin(user: Optional[User]) -> bool:
    return user is not None and (getattr(user, "role", None) == "admin" or bool(user.is_admin))


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
def register(
    request: Request,
    user_in: UserCreate,
    db: Session = Depends(get_db),
    creator: Optional[User] = Depends(get_optional_user),
):
    # Security: registration is admin-only unless explicitly opened. Without this,
    # anyone on the internet could create an account on a customer's box.
    if not settings.ALLOW_OPEN_REGISTRATION and not _is_admin(creator):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled. An administrator must create your account.",
        )

    # Check if user exists
    db_user = db.query(User).filter(User.email == user_in.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and save
    new_user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=Token)
# NOTE: slowapi's in-memory store is per-worker, so with --workers 2 the
# effective limit is ~2x this. Tuned low to compensate; for an exact,
# worker-independent cap use nginx limit_req or a shared (Redis) store.
@limiter.limit("5/minute")
def login(request: Request, db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}