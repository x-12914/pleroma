from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Neon Fix: Ensure sslmode is required
url = settings.DATABASE_URL
if "sslmode" not in url:
    url += "?sslmode=require"

engine = create_engine(
    url,
    pool_pre_ping=True,  # <--- Fixes the 503/SSL errors
    pool_recycle=300     # <--- Closes stale Neon connections
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE IF EXISTS detection_logs ADD COLUMN IF NOT EXISTS report_data JSONB"
            )
        )
        # Role column for RBAC. Add if missing, then backfill from is_admin so
        # existing accounts keep their privileges (admins stay admins; non-admins
        # default to 'analyst' rather than the more-restrictive 'viewer' since
        # they predate the role distinction).
        conn.execute(
            text(
                "ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS role VARCHAR DEFAULT 'viewer'"
            )
        )
        conn.execute(
            text(
                "UPDATE users SET role = 'admin' WHERE is_admin = true AND (role IS NULL OR role = 'viewer')"
            )
        )
        conn.execute(
            text(
                "UPDATE users SET role = 'analyst' WHERE is_admin = false AND (role IS NULL OR role = 'viewer')"
            )
        )

    # Seed the autonomous-response singletons (enforcement_state, allowlist,
    # default policy rules). Idempotent and non-fatal: a failure here must not
    # stop the backend from booting.
    try:
        from app.services.response.bootstrap import bootstrap_response
        db = SessionLocal()
        try:
            bootstrap_response(db)
        finally:
            db.close()
    except Exception as exc:
        print(f"Warning: response bootstrap skipped: {exc}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()