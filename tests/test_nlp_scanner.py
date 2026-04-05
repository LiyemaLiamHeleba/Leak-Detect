"""
Tests for the NLP scanner.
When presidio is not installed, all tests verify graceful fallback.
When presidio IS installed, tests verify actual detection.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.nlp_scanner import NLPScanner, _PRESIDIO_AVAILABLE

scanner = NLPScanner()


def test_nlp_scanner_initializes():
    """NLP scanner must always initialize, even without presidio."""
    assert scanner is not None


def test_nlp_returns_list():
    """scan_text must always return a list."""
    result = scanner.scan_text("Hello, my name is Alice and my email is alice@example.com")
    assert isinstance(result, list)


def test_nlp_graceful_without_presidio():
    """When presidio is absent, scan_text returns empty list (no crash)."""
    if _PRESIDIO_AVAILABLE:
        return  # skip — presidio is installed, different behavior expected
    result = scanner.scan_text("Call me at 555-123-4567 and email bob@company.org")
    assert result == []


def test_nlp_detects_email_when_available():
    """When presidio IS installed, email should be detected."""
    if not _PRESIDIO_AVAILABLE:
        return  # skip — presidio not installed
    result = scanner.scan_text("Contact alice@example.com for help.")
    types = [r["entity_type"] for r in result]
    assert "EMAIL_ADDRESS" in types


def test_nlp_result_schema():
    """Each result dict (when presidio is available) must have required keys."""
    if not _PRESIDIO_AVAILABLE:
        return
    results = scanner.scan_text("My SSN is 123-45-6789")
    for r in results:
        assert "entity_type" in r
        assert "score"       in r
        assert "snippet"     in r
        assert r["score"] >= 0.0
        assert r["score"] <= 1.0


def test_nlp_high_confidence_only():
    """Results should only include detections with score > 0.7."""
    if not _PRESIDIO_AVAILABLE:
        return
    results = scanner.scan_text("Call 555-867-5309 or email test@domain.com")
    for r in results:
        assert r["score"] > 0.7
