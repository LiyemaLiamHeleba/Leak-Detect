"""
Isolation Forest anomaly detector.

Trains on historical scan data from the DB, persists the model to disk,
and writes anomaly results back into the DB (anomaly_results table).

Usage
-----
Train + score all existing scans:
    python -m ml.train

Score new files as they arrive (called from pipeline):
    from ml.anomaly_detector import AnomalyDetector
    detector = AnomalyDetector.load()
    is_anomaly, score = detector.predict_one(file_row_dict)
"""

import os
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

MODEL_PATH = Path(os.getenv("MODEL_PATH", "ml/model.pkl"))


class AnomalyDetector:

    FEATURES = ["risk_score", "size_bytes", "file_type_enc",
                 "hour", "is_weekend", "is_alert", "detection_count"]

    def __init__(self, contamination: float = 0.05):
        self.model         = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            random_state=42,
        )
        self.le            = LabelEncoder()
        self._fitted       = False
        self._le_classes   = None   # saved so predict works after load

    # ------------------------------------------------------------------ #
    #  Feature engineering                                                 #
    # ------------------------------------------------------------------ #
    def _build_features(self, df: pd.DataFrame, fit_encoder: bool = False) -> pd.DataFrame:
        d = df.copy()

        # encode file type
        if fit_encoder:
            d["file_type_enc"] = self.le.fit_transform(d["file_type"].fillna("unknown"))
            self._le_classes   = list(self.le.classes_)
        else:
            # handle unseen types gracefully
            known = self._le_classes or []
            d["file_type"] = d["file_type"].fillna("unknown").apply(
                lambda x: x if x in known else "unknown"
            )
            if known:
                self.le.classes_ = np.array(known)
            d["file_type_enc"] = self.le.transform(d["file_type"])

        d["hour"]            = pd.to_datetime(d["scanned_at"]).dt.hour
        d["is_weekend"]      = (pd.to_datetime(d["scanned_at"]).dt.weekday >= 5).astype(int)
        d["is_alert"]        = d["alert"].fillna(False).astype(int)
        d["detection_count"] = d.get("detection_count", pd.Series(0, index=d.index)).fillna(0)

        return d[self.FEATURES].fillna(0)

    # ------------------------------------------------------------------ #
    #  Train                                                               #
    # ------------------------------------------------------------------ #
    def fit(self, df: pd.DataFrame) -> "AnomalyDetector":
        X            = self._build_features(df, fit_encoder=True)
        self.model.fit(X)
        self._fitted = True
        print(f"[AnomalyDetector] Trained on {len(X)} samples  "
              f"(contamination={self.model.contamination})")
        return self

    # ------------------------------------------------------------------ #
    #  Predict (batch)                                                     #
    # ------------------------------------------------------------------ #
    def predict(self, df: pd.DataFrame):
        if not self._fitted:
            raise RuntimeError("Call fit() before predict().")
        X      = self._build_features(df)
        labels = self.model.predict(X)            # 1=normal, -1=anomaly
        scores = self.model.decision_function(X)  # lower = more anomalous
        return (
            pd.Series(labels == -1, name="is_anomaly",    index=df.index),
            pd.Series(np.round(scores, 4), name="anomaly_score", index=df.index),
        )

    # ------------------------------------------------------------------ #
    #  Predict single row (for pipeline integration)                      #
    # ------------------------------------------------------------------ #
    def predict_one(self, row: dict) -> tuple[bool, float]:
        """Pass a dict matching scanned_files columns. Returns (is_anomaly, score)."""
        df             = pd.DataFrame([row])
        is_anom, score = self.predict(df)
        return bool(is_anom.iloc[0]), float(score.iloc[0])

    # ------------------------------------------------------------------ #
    #  Persist                                                             #
    # ------------------------------------------------------------------ #
    def save(self, path: Path = MODEL_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        print(f"[AnomalyDetector] Model saved → {path}")

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "AnomalyDetector":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        print(f"[AnomalyDetector] Model loaded ← {path}")
        return obj
