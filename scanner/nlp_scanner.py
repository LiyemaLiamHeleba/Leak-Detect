"""
NLP-based PII scanner using Microsoft Presidio.
Falls back gracefully if Presidio is not installed.
"""

try:
    from presidio_analyzer import AnalyzerEngine
    _PRESIDIO_AVAILABLE = True
except ImportError:
    _PRESIDIO_AVAILABLE = False


class NLPScanner:
    def __init__(self):
        if _PRESIDIO_AVAILABLE:
            self.analyzer = AnalyzerEngine()
        else:
            print("[NLPScanner] presidio-analyzer not installed. NLP scanning disabled.")
            self.analyzer = None

    def scan_text(self, text: str) -> list:
        if not self.analyzer:
            return []

        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=[
                "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS",
                "CREDIT_CARD", "IP_ADDRESS", "IBAN_CODE", "US_SSN",
            ],
        )
        return [
            {
                "entity_type": r.entity_type,
                "score":       round(r.score, 3),
                "start":       r.start,
                "end":         r.end,
                "snippet":     text[max(0, r.start - 20): r.end + 20],
            }
            for r in results
            if r.score > 0.7
        ]
