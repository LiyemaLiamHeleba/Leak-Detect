"""
SQLAlchemy session factory.

Usage:
    from db.session import SessionLocal

    session = SessionLocal()
    try:
        session.add(obj)
        session.commit()
    finally:
        session.close()
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///leakdetect.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
