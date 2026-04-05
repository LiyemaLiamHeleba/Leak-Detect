"""
Writes enriched scan results into the database.
Called by run_demo.py and pipeline/flow.py.
"""
from datetime import datetime, timezone
from db.models import ScannedFile, Detection
from db.session import SessionLocal


def insert_scan_result(result: dict, owner_id: str = None) -> str:
    """
    Persist one enriched scan result. Returns the new file UUID.
    Always redacts — never stores raw sensitive values.
    """
    session = SessionLocal()
    try:
        file_row = ScannedFile(
            filename   = result["filename"],
            filepath   = result["filepath"],
            file_type  = result["file_type"],
            size_bytes = result["size_bytes"],
            severity   = result["severity"],
            risk_score = result["risk_score"],
            data_types = result["data_types"],
            alert      = result["alert"],
            owner_id   = owner_id,
            scanned_at = datetime.now(timezone.utc).replace(tzinfo=None),
        )
        session.add(file_row)
        session.flush()

        for d in result.get("regex_detections", []):
            session.add(Detection(
                file_id      = file_row.id,
                pattern_type = d.pattern_type,
                severity     = d.severity,
                line_number  = d.line_number,
                context      = d.context,
                source       = "regex",
            ))

        for d in result.get("nlp_detections", []):
            session.add(Detection(
                file_id      = file_row.id,
                pattern_type = d["entity_type"],
                severity     = "MEDIUM",
                line_number  = 0,
                context      = d["snippet"][:120],
                source       = "nlp",
                nlp_score    = d["score"],
            ))

        session.commit()
        print(f"[DB] {result['filename']:<30} "
              f"risk={result['risk_score']:<6} "
              f"severity={result['severity']:<8} "
              f"alert={result['alert']}")
        return file_row.id

    except Exception as e:
        session.rollback()
        print(f"[DB] Error saving '{result.get('filename')}': {e}")
        raise
    finally:
        session.close()
