"""
Database helper functions (used by tests and utilities).
The main pipeline uses pipeline/db_writer.py directly.
"""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from db.models import User, ScannedFile, RiskEvent


def get_or_create_user(session: Session, username: str):
    if not username:
        return None
    user = session.query(User).filter_by(username=username).first()
    if not user:
        user = User(username=username)
        session.add(user)
        session.flush()
    return user


def update_user_risk(session: Session, user_id: str, delta: float):
    user = session.get(User, user_id)
    if user:
        user.risk_score      = min(round(user.risk_score + delta, 2), 100.0)
        user.violation_count += 1
        user.last_violation  = datetime.now(timezone.utc).replace(tzinfo=None)
        session.commit()
