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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()