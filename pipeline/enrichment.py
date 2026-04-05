"""
Enrichment step: adds severity, risk_score, data_types and alert flag
to a raw scan result dict coming out of FileScanner.
"""

from scanner.patterns import Detection

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    4,
    "LOW":       1,
}

# Reverse lookup: weight → label
_WEIGHT_TO_SEV = {v: k for k, v in SEVERITY_WEIGHTS.items()}


def classify_severity(detections: list) -> str:
    if not detections:
        return "CLEAN"
    max_w = max(SEVERITY_WEIGHTS.get(d.severity, 1) for d in detections)
    return _WEIGHT_TO_SEV.get(max_w, "LOW")


def compute_risk_score(detections: list) -> float:
    """
    0–100 score.
    Considers total weighted count + diversity bonus.
    """
    if not detections:
        return 0.0
    total        = sum(SEVERITY_WEIGHTS.get(d.severity, 1) for d in detections)
    unique_types = len({d.pattern_type for d in detections})
    raw          = total * (1 + 0.1 * unique_types)
    return min(round(raw, 2), 100.0)


def enrich(scan_result: dict) -> dict:
    detections = scan_result.get("regex_detections", [])
    scan_result["severity"]   = classify_severity(detections)
    scan_result["risk_score"] = compute_risk_score(detections)
    scan_result["data_types"] = list({d.pattern_type for d in detections})
    scan_result["alert"]      = scan_result["risk_score"] >= 10
    return scan_result
