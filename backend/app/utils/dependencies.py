from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.database import get_db
from app.db.models import User
from app.schemas.schemas import TokenData

# If you are using /api/v1 prefix, it MUST be included here
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

# 1. This function gets the logged-in user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
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

# 2. NEW: This function checks if that user is an admin
def get_current_admin(current_user: User = Depends(get_current_user)):
    """
    Checks if the current authenticated user has admin privileges.
    Used for sensitive routes like model retraining.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted. Admin privileges required."
        )
    return current_user