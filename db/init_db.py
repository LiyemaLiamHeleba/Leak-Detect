"""
Creates all database tables.
Run once before using the system:
    python -m db.init_db

Safe to run multiple times — uses create_all which skips existing tables.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine
from db.models import Base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///leakdetect.db")


def init():
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    )
    Base.metadata.create_all(engine)
    print(f"[DB] Tables ready — {DATABASE_URL}")
    return engine


if __name__ == "__main__":
    init()
