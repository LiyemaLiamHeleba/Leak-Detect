"""
Insider threat detection — 4 DLP rules.
Called after every file is stored. Evaluates the owning user's behaviour
and creates RiskEvent rows when rules are triggered.
"""
from datetime import datetime, timezone, timedelta
from db.models import ScannedFile, User, RiskEvent
from db.session import SessionLocal

THRESHOLDS = {
    "repeated_violations":  3,   # same user, >3 alerts in 24 h
    "bulk_files_per_hour":  10,  # >10 files scanned in 1 h by same user
    "off_hours_start":      22,  # 10 pm
    "off_hours_end":        6,   # 6 am
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class InsiderThreatDetector:

    def evaluate(self, file_id: str) -> list:
        """Run all 4 rules against a newly stored file. Returns list of RiskEvents created."""
        session = SessionLocal()
        try:
            file = session.get(ScannedFile, file_id)
            if not file:
                return []

            events = []
            if file.owner_id:
                events += self._check_repeated(file, session)
                events += self._check_off_hours(file)
                events += self._check_bulk(file, session)
            if file.severity == "CRITICAL":
                events.append(self._flag_critical(file))

            for ev in events:
                session.add(ev)
                if ev.user_id:
                    user = session.get(User, ev.user_id)
                    if user:
                        user.risk_score      = min(100.0, round(user.risk_score + ev.score_delta, 2))
                        user.violation_count += 1
                        user.last_violation  = _now()

            session.commit()
            return events

        except Exception as e:
            session.rollback()
            print(f"[ThreatDetector] Error on file {file_id}: {e}")
            return []
        finally:
            session.close()

    # ── Rule 1: Repeated leaks ────────────────────────────────────────────────
    def _check_repeated(self, file: ScannedFile, session) -> list:
        window = _now() - timedelta(hours=24)
        count  = (session.query(ScannedFile)
                  .filter(ScannedFile.owner_id == file.owner_id,
                          ScannedFile.alert    == True,
                          ScannedFile.scanned_at >= window)
                  .count())
        if count >= THRESHOLDS["repeated_violations"]:
            return [RiskEvent(
                user_id     = file.owner_id,
                file_id     = file.id,
                event_type  = "repeated_leak",
                score_delta = 15.0,
                metadata_   = {"violations_in_24h": count},
            )]
        return []

    # ── Rule 2: Off-hours activity ────────────────────────────────────────────
    def _check_off_hours(self, file: ScannedFile) -> list:
        hour   = file.scanned_at.hour
        is_off = hour >= THRESHOLDS["off_hours_start"] or hour < THRESHOLDS["off_hours_end"]
        if is_off and file.alert:
            return [RiskEvent(
                user_id     = file.owner_id,
                file_id     = file.id,
                event_type  = "off_hours_activity",
                score_delta = 10.0,
                metadata_   = {"hour": hour},
            )]
        return []

    # ── Rule 3: Bulk exfiltration ─────────────────────────────────────────────
    def _check_bulk(self, file: ScannedFile, session) -> list:
        window = _now() - timedelta(hours=1)
        count  = (session.query(ScannedFile)
                  .filter(ScannedFile.owner_id  == file.owner_id,
                          ScannedFile.scanned_at >= window)
                  .count())
        if count >= THRESHOLDS["bulk_files_per_hour"]:
            return [RiskEvent(
                user_id     = file.owner_id,
                file_id     = file.id,
                event_type  = "bulk_exfiltration",
                score_delta = 20.0,
                metadata_   = {"files_in_1h": count},
            )]
        return []

    # ── Rule 4: Critical detection ────────────────────────────────────────────
    def _flag_critical(self, file: ScannedFile) -> RiskEvent:
        return RiskEvent(
            user_id     = file.owner_id,
            file_id     = file.id,
            event_type  = "critical_detection",
            score_delta = 25.0,
            metadata_   = {"severity": file.severity, "risk_score": file.risk_score},
        )
