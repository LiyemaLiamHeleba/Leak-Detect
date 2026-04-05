"""
End-to-end demo — no Prefect needed.

Steps:
  1. Initialise the database (creates tables if missing)
  2. Generate 11 synthetic sample files with realistic PII
  3. Scan every file (regex + NLP if available)
  4. Enrich results (severity, risk score, alert flag)
  5. Store results in the database
  6. Run insider threat detection on each file
  7. Train the ML anomaly model
  8. Print a summary

Run:  python run_demo.py
"""

import os
import sys
import glob

sys.path.insert(0, os.path.dirname(__file__))

# ── 1. Init DB ────────────────────────────────────────────────────────────────
print("── Step 1/7  Initialising database ──────────────────────────────────")
from db.init_db import init
engine = init()

# ── 2. Generate sample files ──────────────────────────────────────────────────
print("\n── Step 2/7  Generating synthetic sample files ───────────────────────")
import subprocess
subprocess.run([sys.executable, "data/generate_samples.py"], check=True)

# ── 3–6. Scan → Enrich → Store → Threat detect ───────────────────────────────
print("\n── Step 3–6/7  Scanning files ────────────────────────────────────────")
from scanner.file_scanner import FileScanner
from pipeline.enrichment import enrich
from pipeline.db_writer import insert_scan_result
from security.insider_threat import InsiderThreatDetector

scanner  = FileScanner()
detector = InsiderThreatDetector()
files    = glob.glob("data/sample_files/**/*.*", recursive=True)

print(f"Found {len(files)} files\n")

stored_ids = []
for path in sorted(files):
    raw      = scanner.scan_file(path)
    enriched = enrich(raw)
    fid      = insert_scan_result(enriched)
    stored_ids.append(fid)
    detector.evaluate(fid)

# ── 7. Train ML model ─────────────────────────────────────────────────────────
print("\n── Step 7/7  Training ML anomaly model ───────────────────────────────")
from ml.train import main as train_ml
train_ml()

# ── Summary ───────────────────────────────────────────────────────────────────
from db.session import SessionLocal
from db.models import ScannedFile, Detection, RiskEvent
from sqlalchemy import text

session     = SessionLocal()
total_files  = session.query(ScannedFile).count()
total_dets   = session.query(Detection).count()
total_alerts = session.query(ScannedFile).filter(ScannedFile.alert == True).count()
total_events = session.query(RiskEvent).count()

try:
    total_anomalies = session.execute(
        text("SELECT COUNT(*) FROM anomaly_results WHERE is_anomaly = 1")
    ).scalar()
except Exception:
    total_anomalies = "n/a (run ml.train first)"

session.close()

print(f"""
╔═══════════════════════════════════════════╗
║            DEMO COMPLETE                  ║
╠═══════════════════════════════════════════╣
║  Files scanned     : {total_files:<22}║
║  Detections found  : {total_dets:<22}║
║  Alerts raised     : {total_alerts:<22}║
║  Threat events     : {total_events:<22}║
║  ML anomalies      : {str(total_anomalies):<22}║
╚═══════════════════════════════════════════╝

Next steps:
  python -m streamlit run dashboard/app.py   ← launch dashboard
  python -m security.user_manager add --username alice --department Engineering
  python -m security.user_manager assign --username alice --directory ./data/sample_files
  python -m ml.train                         ← retrain ML model
  pytest tests/ -v                           ← run test suite
""")
