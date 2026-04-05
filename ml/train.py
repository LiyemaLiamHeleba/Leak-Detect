"""
ML training script — Isolation Forest anomaly detection.

Steps:
  1. Load all scanned files from DB + detection counts
  2. Train Isolation Forest on 7 features
  3. Score every file
  4. Write results to anomaly_results table
  5. Save model to ml/model.pkl

Run:
  python -m ml.train
  python -m ml.train --contamination 0.10
"""
import argparse
import os
import sys
import uuid
from datetime import datetime, timezone

import pandas as pd
from sqlalchemy import create_engine, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.anomaly_detector import AnomalyDetector

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///leakdetect.db")


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def load_training_data(engine) -> pd.DataFrame:
    with engine.connect() as conn:
        files = pd.read_sql("SELECT * FROM scanned_files", conn)
        det_counts = pd.read_sql(
            "SELECT file_id, COUNT(*) AS detection_count FROM detections GROUP BY file_id",
            conn,
        )
    df = files.merge(det_counts, left_on="id", right_on="file_id", how="left")
    df["detection_count"] = df["detection_count"].fillna(0)
    return df


def ensure_anomaly_table(engine):
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS anomaly_results (
                id            TEXT PRIMARY KEY,
                file_id       TEXT NOT NULL,
                is_anomaly    INTEGER NOT NULL,
                anomaly_score REAL NOT NULL,
                scored_at     TEXT NOT NULL,
                model_version TEXT
            )
        """))
        conn.commit()


def write_results(engine, df: pd.DataFrame, is_anomaly, anomaly_score,
                  model_version: str):
    rows = []
    for i, file_id in enumerate(df["id"]):
        rows.append({
            "id":            str(uuid.uuid4()),
            "file_id":       file_id,
            "is_anomaly":    int(is_anomaly.iloc[i]),
            "anomaly_score": float(anomaly_score.iloc[i]),
            "scored_at":     _now_str(),
            "model_version": model_version,
        })
    result_df = pd.DataFrame(rows)
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM anomaly_results"))
        conn.commit()
    result_df.to_sql("anomaly_results", engine, if_exists="append", index=False)
    print(f"[ML] Wrote {len(rows)} anomaly scores to DB.")


def main(contamination: float = 0.05):
    from db.init_db import init
    engine = init()
    ensure_anomaly_table(engine)

    print("[ML] Loading scan data...")
    df = load_training_data(engine)

    if len(df) < 5:
        print("[ML] Need at least 5 scanned files to train. Run run_demo.py first.")
        return

    version = f"iforest-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    print(f"[ML] Training on {len(df)} samples (contamination={contamination})...")
    detector = AnomalyDetector(contamination=contamination)
    detector.fit(df)

    is_anomaly, anomaly_score = detector.predict(df)
    n_anom = int(is_anomaly.sum())
    print(f"[ML] Anomalies flagged: {n_anom} / {len(df)}")

    write_results(engine, df, is_anomaly, anomaly_score, model_version=version)
    detector.save()

    # Print top anomalies
    df["is_anomaly"]    = is_anomaly.values
    df["anomaly_score"] = anomaly_score.values
    top = (df[df["is_anomaly"]]
           .sort_values("anomaly_score")
           [["filename", "risk_score", "severity", "anomaly_score"]]
           .head(5))
    if not top.empty:
        print("\n[ML] Top anomalous files:")
        print(top.to_string(index=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()
    main(args.contamination)
