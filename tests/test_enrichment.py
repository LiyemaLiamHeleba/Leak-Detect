import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scanner.patterns import Detection
from pipeline.enrichment import classify_severity, compute_risk_score, enrich

def det(sev):
    return Detection("email","***",sev,1,"")

def test_clean():
    assert classify_severity([]) == "CLEAN"

def test_critical():
    assert classify_severity([det("CRITICAL")]) == "CRITICAL"

def test_zero_score():
    assert compute_risk_score([]) == 0.0

def test_score_cap():
    assert compute_risk_score([det("CRITICAL")] * 20) <= 100.0

def test_enrich_alert():
    r = {"filename":"t.txt","filepath":"/t.txt","file_type":".txt","size_bytes":100,
         "regex_detections":[det("CRITICAL")],"nlp_detections":[]}
    e = enrich(r)
    assert e["alert"] == True
    assert "risk_score" in e
