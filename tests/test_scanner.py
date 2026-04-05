import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scanner.patterns import RegexScanner

scanner = RegexScanner()

def dets(text, ptype):
    return [d for d in scanner.scan_text(text) if d.pattern_type == ptype]

def test_email_detected():
    assert len(dets("Contact support@example.com", "email")) >= 1

def test_credit_card_detected():
    assert len(dets("Card: 4111111111111111", "credit_card")) >= 1

def test_credit_card_redacted():
    hits = dets("Card: 4111111111111111", "credit_card")
    assert "4111111111111111" not in hits[0].value

def test_aws_key_detected():
    assert len(dets("key=AKIAIOSFODNN7EXAMPLE", "aws_key")) >= 1

def test_password_detected():
    assert len(dets("password=S3cr3tP@ss!", "password")) >= 1

def test_private_key_detected():
    assert len(dets("-----BEGIN RSA PRIVATE KEY-----", "private_key")) >= 1

def test_ssn_detected():
    assert len(dets("SSN: 123-45-6789", "ssn")) >= 1

def test_clean_text():
    assert len(scanner.scan_text("The quick brown fox jumps over the lazy dog.")) == 0

def test_critical_severity():
    hits = dets("Card: 4111111111111111", "credit_card")
    assert hits[0].severity == "CRITICAL"
