"""
Multi-format file scanner. Extracts text from .txt, .csv, .eml, .json, .log
then runs both regex and NLP scanners over the content.
"""

import csv
import email
import json
from pathlib import Path

from scanner.patterns import RegexScanner
from scanner.nlp_scanner import NLPScanner


class FileScanner:
    def __init__(self):
        self.regex_scanner = RegexScanner()
        self.nlp_scanner   = NLPScanner()

    def scan_file(self, filepath: str) -> dict:
        path  = Path(filepath)
        text  = self._extract_text(path)
        regex = self.regex_scanner.scan_text(text)
        nlp   = self.nlp_scanner.scan_text(text)

        return {
            "filename":          path.name,
            "filepath":          str(path.resolve()),
            "size_bytes":        path.stat().st_size,
            "file_type":         path.suffix.lower(),
            "regex_detections":  regex,
            "nlp_detections":    nlp,
            "raw_text_length":   len(text),
        }

    def _extract_text(self, path: Path) -> str:
        suffix = path.suffix.lower()
        try:
            if suffix == ".csv":
                with open(path, newline="", errors="ignore") as f:
                    rows = list(csv.reader(f))
                return "\n".join(" ".join(row) for row in rows)

            elif suffix == ".eml":
                with open(path, "rb") as f:
                    msg = email.message_from_bytes(f.read())
                parts = []
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            parts.append(part.get_payload(decode=True).decode("utf-8", errors="ignore"))
                else:
                    parts.append(msg.get_payload(decode=True).decode("utf-8", errors="ignore"))
                return "\n".join(parts)

            elif suffix == ".json":
                with open(path, errors="ignore") as f:
                    data = json.load(f)
                return json.dumps(data, indent=2)

            else:  # .txt, .log, .py, etc.
                return path.read_text(errors="ignore")

        except Exception as e:
            print(f"[FileScanner] Could not read {path.name}: {e}")
            return ""
