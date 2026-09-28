"""Runs every detector and resolves overlapping matches."""
from __future__ import annotations

from dataclasses import dataclass

from .patterns import DETECTORS, Detector


@dataclass(frozen=True)
class Span:
    entity: str
    start: int
    end: int
    text: str
    score: float


class DetectionEngine:
    def __init__(self, detectors: list[Detector] | None = None, min_score: float = 0.5,
                 use_presidio: bool = False):
        self.detectors = detectors or DETECTORS
        self.min_score = min_score
        self.presidio = None
        if use_presidio:
            try:  # optional heavy dependency
                from presidio_analyzer import AnalyzerEngine
                self.presidio = AnalyzerEngine()
            except ImportError:
                self.presidio = None

    def _regex_spans(self, text: str) -> list[Span]:
        spans = []
        for d in self.detectors:
            for m in d.pattern.finditer(text):
                value = m.group(d.group)
                if d.validator and not d.validator(value):
                    continue
                start, end = m.span(d.group)
                spans.append(Span(d.entity, start, end, value, d.score))
        return spans

    def _presidio_spans(self, text: str) -> list[Span]:
        if not self.presidio:
            return []
        out = []
        for r in self.presidio.analyze(text=text, language="en", entities=["PERSON", "LOCATION"]):
            out.append(Span(r.entity_type, r.start, r.end, text[r.start:r.end], r.score))
        return out

    def detect(self, text: str) -> list[Span]:
        """Return non-overlapping spans, sorted by position.

        When two matches overlap we keep the higher score, then the longer one
        (e.g. a DOB beats a plain DATE on the same characters).
        """
        candidates = [s for s in self._regex_spans(text) + self._presidio_spans(text)
                      if s.score >= self.min_score]
        candidates.sort(key=lambda s: (-s.score, -(s.end - s.start), s.start))
        chosen: list[Span] = []
        for s in candidates:
            if all(s.end <= c.start or s.start >= c.end for c in chosen):
                chosen.append(s)
        return sorted(chosen, key=lambda s: s.start)
