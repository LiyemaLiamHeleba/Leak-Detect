"""
SQLAlchemy ORM models.
Default DB: SQLite (leakdetect.db in project root).
Switch to PostgreSQL by setting DATABASE_URL in .env.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, Float,
                        ForeignKey, Integer, JSON, String, Text)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id              = Column(String,  primary_key=True, default=_uuid)
    username        = Column(String,  unique=True, nullable=False)
    department      = Column(String,  default="Unknown")
    risk_score      = Column(Float,   default=0.0)
    violation_count = Column(Integer, default=0)
    last_violation  = Column(DateTime, nullable=True)

    files  = relationship("ScannedFile", back_populates="owner")
    events = relationship("RiskEvent",   back_populates="user")


class ScannedFile(Base):
    __tablename__ = "scanned_files"

    id          = Column(String,  primary_key=True, default=_uuid)
    filename    = Column(String,  nullable=False)
    filepath    = Column(String,  nullable=False)
    file_type   = Column(String)
    size_bytes  = Column(Integer)
    scanned_at  = Column(DateTime, default=_now)
    severity    = Column(String)   # CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    risk_score  = Column(Float,    default=0.0)
    data_types  = Column(JSON)     # list of detected pattern type strings
    alert       = Column(Boolean,  default=False)
    owner_id    = Column(String,   ForeignKey("users.id"), nullable=True)

    owner      = relationship("User",      back_populates="files")
    detections = relationship("Detection", back_populates="file",
                              cascade="all, delete-orphan")
    events     = relationship("RiskEvent", back_populates="file")


class Detection(Base):
    __tablename__ = "detections"

    id           = Column(String,  primary_key=True, default=_uuid)
    file_id      = Column(String,  ForeignKey("scanned_files.id"))
    pattern_type = Column(String)
    severity     = Column(String)
    line_number  = Column(Integer)
    context      = Column(Text)          # redacted snippet only
    detected_at  = Column(DateTime, default=_now)
    source       = Column(String)        # "regex" or "nlp"
    nlp_score    = Column(Float, nullable=True)

    file = relationship("ScannedFile", back_populates="detections")


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id          = Column(String,  primary_key=True, default=_uuid)
    user_id     = Column(String,  ForeignKey("users.id"),         nullable=True)
    file_id     = Column(String,  ForeignKey("scanned_files.id"), nullable=True)
    event_type  = Column(String)   # repeated_leak / off_hours_activity /
                                   # bulk_exfiltration / critical_detection
    score_delta = Column(Float,    default=0.0)
    metadata_   = Column("metadata", JSON)
    created_at  = Column(DateTime, default=_now)

    user = relationship("User",        back_populates="events")
    file = relationship("ScannedFile", back_populates="events")
