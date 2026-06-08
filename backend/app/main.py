from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from sqlalchemy.exc import OperationalError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.db.database import init_db
from app.api.routes import auth, logs, analysis, sensors, ingest
from app.core.rate_limiter import limiter
from app.core.config import settings
from app.utils.dependencies import get_current_user

# Initialize database schema and indexes if possible
try:
    init_db()
except Exception as exc:
    print(f"Warning: database initialization failed on startup: {exc}")

app = FastAPI(title="AICDS AI Threat Detection")

# Enable CORS for frontend cross-origin requests
origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE", "PUT"],
    allow_headers=["Content-Type", "Authorization", "Set-Cookie", "Access-Control-Allow-Origin"],
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include routers with /api/v1 prefix
app.include_router(auth.router, prefix="/api/v1")
app.include_router(logs.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(sensors.router, prefix="/api/v1")
app.include_router(ingest.router, prefix="/api/v1")


@app.api_route("/", methods=["GET", "HEAD"])
async def health_check(request: Request):
    return {"status": "online", "message": "AICDS System Active"}

# Example of a protected route
@app.get("/api/v1/me")
def read_users_me(current_user=Depends(get_current_user)):
    # Resolve role with the same fallback the auth dependency uses, so /me
    # never returns null on accounts that predate the role column.
    role = getattr(current_user, "role", None)
    if not role:
        role = "admin" if current_user.is_admin else "analyst"
    return {
        "id": current_user.id,
        "email": current_user.email,
        "is_admin": bool(current_user.is_admin),
        "role": role,
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, (OperationalError, httpx.HTTPError, TimeoutError)):
        return JSONResponse(
            status_code=503,
            content={"detail": "Service temporarily unavailable. Please retry later."},
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )