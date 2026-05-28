import sys
import os

# Add the current directory to the path so we can import 'app'
sys.path.append(os.getcwd())

from sqlalchemy.orm import Session
from app.db.database import engine, Base, SessionLocal
from app.db.models import User, DetectionLog, AnalysisTask, Feedback
from app.core.security import hash_password

def reset_database():
    print("🚀 Connecting to Neon Database...")
    
    # 1. Warning
    confirm = input("⚠️ This will DELETE all data in your Neon DB. Continue? (y/n): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    # 2. Drop and Create
    print("🗑️ Dropping existing tables...")
    Base.metadata.drop_all(bind=engine)
    
    print("🏗️ Creating new table structure...")
    Base.metadata.create_all(bind=engine)
    
    # 3. Seed an Admin User
    print("👤 Creating default admin user...")
    db = SessionLocal()
    try:
        admin_email = "admin@aicds.com"
        # Check if exists (shouldn't, since we just dropped tables)
        admin_user = User(
            email=admin_email,
            hashed_password=hash_password("admin123"), # Change this later!
            is_admin=True,
            is_active=True
        )
        db.add(admin_user)
        db.commit()
        print(f"✅ Success! Admin created: {admin_email} / admin123")
    except Exception as e:
        print(f"❌ Error seeding admin: {e}")
        db.rollback()
    finally:
        db.close()

    print("\n✨ Database is now in sync with your models.py!")

if __name__ == "__main__":
    reset_database()