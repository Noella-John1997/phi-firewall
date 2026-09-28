"""Regex detectors for each entity type.

Each detector = (entity, regex, optional validator, score).
The regex finds candidates; the validator (checksum) confirms them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from . import validators as v


@dataclass(frozen=True)
class Detector:
    entity: str
    pattern: re.Pattern
    validator: Callable[[str], bool] | None = None
    score: float = 0.9
    group: int = 0  # which regex group is the sensitive value


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


MONTHS = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
DATE = rf"(?:\d{{1,2}}[/-]\d{{1,2}}[/-]\d{{2,4}}|\d{{4}}-\d{{2}}-\d{{2}}|\d{{1,2}} {MONTHS},? \d{{4}}|{MONTHS} \d{{1,2}},? \d{{4}})"

DETECTORS: list[Detector] = [
    Detector("EMAIL", _r(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), score=0.99),
    Detector("CREDIT_CARD", _r(r"\b(?:\d[ -]?){13,19}\b"), v.luhn_valid, 0.95),
    Detector("AADHAAR", _r(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), v.aadhaar_valid, 0.97),
    Detector("PAN", _r(r"\b[A-Z]{5}\d{4}[A-Z]\b"), v.pan_valid, 0.95),
    Detector("SSN", _r(r"\b\d{3}-\d{2}-\d{4}\b"), v.ssn_valid, 0.95),
    Detector("NPI", _r(r"\bNPI[:#\s]*(\d{10})\b", re.I), v.npi_valid, 0.95, group=1),
    Detector("MRN", _r(r"\b(?:MRN|medical record(?: number| no\.?)?)[:#\s]*([A-Z0-9-]{5,12})\b", re.I), score=0.9, group=1),
    Detector("DOB", _r(rf"\b(?:DOB|D\.O\.B\.|date of birth|born(?: on)?)[:\s]*({DATE})", re.I), score=0.95, group=1),
    Detector("DATE", _r(rf"\b{DATE}\b", re.I), score=0.6),
    Detector("PHONE", _r(r"(?<!\w)(?:\+91[\s-]?[6-9]\d{4}[\s-]?\d{5}|\+?1?[\s.-]?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4})(?!\w)"), score=0.85),
    Detector("IP_ADDRESS", _r(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), score=0.8),
    # Names are hard with regex. We only catch names after strong cues
    # ("Patient: Jane Doe", "Mr. Rao", "Dr. Mehta"). Install Presidio for NER-based names.
    Detector("PERSON", _r(r"\b(?i:patient(?: name)?|name|mr|mrs|ms|dr)\.?[:\s]+([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})"), score=0.75, group=1),
]
