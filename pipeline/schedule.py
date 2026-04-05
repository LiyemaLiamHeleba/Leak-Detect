"""
Prefect scheduled pipeline — scans a directory on a cron schedule
and retrains the ML model when enough new files have accumulated.

Start the scheduler:
  python -m pipeline.schedule

Environment variables:
  SCAN_DIRECTORY        Directory to watch  (default: ./data/sample_files)
  SCAN_CRON             Cron expression     (default: every 30 minutes)
  NEW_FILES_THRESHOLD   Retrain after N new files (default: 5)
  SCAN_OWNER_ID         User UUID to assign files to (optional)
"""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prefect import flow, task

from scanner.file_scanner import FileScanner
from pipeline.enrichment import enrich
from pipeline.db_writer import insert_scan_result
from security.insider_threat import InsiderThreatDetector
from db.session import SessionLocal
from db.models import ScannedFile

SCAN_DIR            = os.getenv("SCAN_DIRECTORY",       "./data/sample_files")
SCAN_CRON           = os.getenv("SCAN_CRON",            "*/30 * * * *")
NEW_FILES_THRESHOLD = int(os.getenv("NEW_FILES_THRESHOLD", "5"))
OWNER_ID            = os.getenv("SCAN_OWNER_ID",        None)

_last_trained_count = 0


@task(retries=2, retry_delay_seconds=10, log_prints=True)
def scan_and_store(path: str) -> str:
    raw      = FileScanner().scan_file(path)
    enriched = enrich(raw)
    return insert_scan_result(enriched, owner_id=OWNER_ID)


@task(log_prints=True)
def run_threat_detection(file_id: str):
    InsiderThreatDetector().evaluate(file_id)


@task(log_prints=True)
def get_file_count() -> int:
    session = SessionLocal()
    try:
        return session.query(ScannedFile).count()
    finally:
        session.close()


@task(log_prints=True)
def maybe_retrain(current_count: int):
    global _last_trained_count
    delta = current_count - _last_trained_count
    if delta >= NEW_FILES_THRESHOLD:
        print(f"[Schedule] {delta} new files since last train — retraining ML model...")
        from ml.train import main as train_ml
        train_ml()
        _last_trained_count = current_count
    else:
        print(f"[Schedule] {delta} new files (need {NEW_FILES_THRESHOLD} to retrain)")


@flow(name="scheduled-leak-scan", log_prints=True)
def scheduled_scan(directory: str = SCAN_DIR):
    files = glob.glob(f"{directory}/**/*.*", recursive=True)
    print(f"[Schedule] Found {len(files)} files in '{directory}'")

    for path in sorted(files):
        fid = scan_and_store(path)
        if fid:
            run_threat_detection(fid)

    count = get_file_count()
    maybe_retrain(count)
    print("[Schedule] Cycle complete.")


if __name__ == "__main__":
    print(f"[Schedule] Starting scheduler — cron: '{SCAN_CRON}'")
    scheduled_scan.serve(name="leak-scan-scheduler", cron=SCAN_CRON)
