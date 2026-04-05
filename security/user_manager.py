"""
User management — create, list, assign files to users.

CLI usage:
    python -m security.user_manager add --username alice --department Engineering
    python -m security.user_manager add --username bob   --department Finance
    python -m security.user_manager list
    python -m security.user_manager assign --username alice --directory ./data/sample_files
    python -m security.user_manager reset  --username alice

Programmatic usage:
    from security.user_manager import UserManager
    mgr = UserManager()
    uid = mgr.create_user("alice", "Engineering")
    mgr.assign_files_to_user("alice", ["file-uuid-1", "file-uuid-2"])
"""

import argparse
import os
import sys
import glob
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.session import SessionLocal
from db.models import User, ScannedFile


class UserManager:

    def create_user(self, username: str, department: str = "Unknown") -> str:
        session = SessionLocal()
        try:
            existing = session.query(User).filter(User.username == username).first()
            if existing:
                print(f"[UserManager] User '{username}' already exists (id={existing.id})")
                return existing.id
            user = User(username=username, department=department)
            session.add(user)
            session.commit()
            print(f"[UserManager] Created user '{username}' in {department} (id={user.id})")
            return user.id
        finally:
            session.close()

    def list_users(self) -> list:
        session = SessionLocal()
        try:
            users = session.query(User).order_by(User.risk_score.desc()).all()
            if not users:
                print("[UserManager] No users found. Add with: python -m security.user_manager add")
                return []
            print(f"\n{'Username':<20} {'Department':<15} {'Risk':>6} {'Violations':>10} {'Last violation'}")
            print("-" * 70)
            for u in users:
                last = u.last_violation.strftime("%Y-%m-%d %H:%M") if u.last_violation else "—"
                print(f"{u.username:<20} {u.department:<15} {u.risk_score:>6.1f} {u.violation_count:>10} {last}")
            return users
        finally:
            session.close()

    def assign_files_to_user(self, username: str, file_ids: list[str]) -> int:
        """Assign specific file IDs to a user."""
        session = SessionLocal()
        try:
            user = session.query(User).filter(User.username == username).first()
            if not user:
                print(f"[UserManager] User '{username}' not found.")
                return 0
            updated = 0
            for fid in file_ids:
                f = session.get(ScannedFile, fid)
                if f:
                    f.owner_id = user.id
                    updated += 1
            session.commit()
            print(f"[UserManager] Assigned {updated} files to '{username}'")
            return updated
        finally:
            session.close()

    def assign_directory_to_user(self, username: str, directory: str) -> int:
        """Assign all scanned files whose filepath starts with directory to a user."""
        session = SessionLocal()
        try:
            user = session.query(User).filter(User.username == username).first()
            if not user:
                print(f"[UserManager] User '{username}' not found.")
                return 0
            files = session.query(ScannedFile).all()
            abs_dir = os.path.abspath(directory)
            updated = 0
            for f in files:
                if f.filepath.startswith(abs_dir):
                    f.owner_id = user.id
                    updated += 1
            session.commit()
            print(f"[UserManager] Assigned {updated} files in '{directory}' to '{username}'")
            return updated
        finally:
            session.close()

    def reset_user(self, username: str):
        """Zero out a user's risk score and violation count."""
        session = SessionLocal()
        try:
            user = session.query(User).filter(User.username == username).first()
            if not user:
                print(f"[UserManager] User '{username}' not found.")
                return
            user.risk_score      = 0.0
            user.violation_count = 0
            user.last_violation  = None
            session.commit()
            print(f"[UserManager] Reset risk data for '{username}'")
        finally:
            session.close()

    def get_high_risk_users(self, threshold: float = 30.0) -> list:
        session = SessionLocal()
        try:
            return (session.query(User)
                    .filter(User.risk_score >= threshold)
                    .order_by(User.risk_score.desc())
                    .all())
        finally:
            session.close()


# ── CLI ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="User management for leak-detect")
    sub    = parser.add_subparsers(dest="cmd")

    p_add = sub.add_parser("add", help="Create a user")
    p_add.add_argument("--username",   required=True)
    p_add.add_argument("--department", default="Unknown")

    sub.add_parser("list", help="List all users and risk scores")

    p_assign = sub.add_parser("assign", help="Assign files in a directory to a user")
    p_assign.add_argument("--username",  required=True)
    p_assign.add_argument("--directory", required=True)

    p_reset = sub.add_parser("reset", help="Zero out a user's risk score")
    p_reset.add_argument("--username", required=True)

    args = parser.parse_args()
    mgr  = UserManager()

    if args.cmd == "add":
        mgr.create_user(args.username, args.department)
    elif args.cmd == "list":
        mgr.list_users()
    elif args.cmd == "assign":
        mgr.assign_directory_to_user(args.username, args.directory)
    elif args.cmd == "reset":
        mgr.reset_user(args.username)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
