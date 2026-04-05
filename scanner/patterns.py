import re
from dataclasses import dataclass

@dataclass
class Detection:
    pattern_type: str
    value: str        # always redacted
    severity: str
    line_number: int
    context: str      # surrounding text, truncated

# (regex, severity)
PATTERNS = {
    "email":       (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "LOW"),
    "credit_card": (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "CRITICAL"),
    "api_key":     (r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "HIGH"),
    "aws_key":     (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "password":    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?(\S{6,})", "HIGH"),
    "private_key": (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "CRITICAL"),
    "ssn":         (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
    "jwt_token":   (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "HIGH"),
    "ip_address":  (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "LOW"),
    "phone":       (r"\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})\b", "MEDIUM"),
}


def redact(value: str) -> str:
    """Never store raw sensitive data. Return a safe redacted form."""
    if len(value) <= 6:
        return "***"
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


class RegexScanner:
    def scan_text(self, text: str) -> list:
        detections = []
        lines = text.splitlines()
        for line_no, line in enumerate(lines, 1):
            for pattern_type, (regex, severity) in PATTERNS.items():
                for match in re.finditer(regex, line):
                    detections.append(Detection(
                        pattern_type=pattern_type,
                        value=redact(match.group(0)),
                        severity=severity,
                        line_number=line_no,
                        context=line.strip()[:120],
                    ))
        return detections
