"""Shared data types for analysis findings and verdicts.

A Finding is one piece of evidence produced by an analyzer. It carries a
severity weight; the engine sums weights into an overall score and maps that
to a verdict band. This is what makes HawkScan explainable: the verdict is
always traceable to the findings that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity of a single finding. The integer value is its score weight."""

    INFO = 0        # contextual, never moves the verdict
    LOW = 10        # mildly unusual
    MEDIUM = 25     # suspicious, worth a human look
    HIGH = 50       # strongly indicative of malicious intent
    CRITICAL = 90   # near-certain malicious signal (e.g. known-bad YARA hit)

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    """One piece of evidence about a file."""

    analyzer: str            # which analyzer produced this
    title: str               # short human-readable summary
    severity: Severity
    detail: str = ""         # longer explanation / context
    category: str = "general"  # e.g. "packer", "macro", "network", "persistence"
    data: dict[str, Any] = field(default_factory=dict)  # structured extras

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["score"] = int(self.severity)
        return d


class Verdict(IntEnum):
    """Final classification band."""

    CLEAN = 0
    LOW_RISK = 1
    SUSPICIOUS = 2
    LIKELY_MALICIOUS = 3
    MALICIOUS = 4

    @property
    def label(self) -> str:
        return {
            Verdict.CLEAN: "Clean",
            Verdict.LOW_RISK: "Low Risk",
            Verdict.SUSPICIOUS: "Suspicious",
            Verdict.LIKELY_MALICIOUS: "Likely Malicious",
            Verdict.MALICIOUS: "Malicious",
        }[self]


# Score thresholds (inclusive lower bound) -> verdict band.
# Tuned so a single HIGH finding alone is "Suspicious", two HIGH or a CRITICAL
# pushes toward malicious. Adjust in one place to retune the whole engine.
VERDICT_THRESHOLDS: list[tuple[int, Verdict]] = [
    (0, Verdict.CLEAN),
    (15, Verdict.LOW_RISK),
    (45, Verdict.SUSPICIOUS),
    (90, Verdict.LIKELY_MALICIOUS),
    (150, Verdict.MALICIOUS),
]


def score_to_verdict(score: int) -> Verdict:
    verdict = Verdict.CLEAN
    for threshold, band in VERDICT_THRESHOLDS:
        if score >= threshold:
            verdict = band
    return verdict
