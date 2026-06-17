"""Entropy analysis: high entropy suggests packing, encryption, or compression."""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyAnalyzer(Analyzer):
    name = "entropy"

    def applies(self, ctx: AnalysisContext) -> bool:
        # Compressed/encrypted container formats are *expected* to be high
        # entropy; flagging them adds noise, so skip those types.
        return ctx.info.file_type not in {
            "zip", "gzip", "7z", "rar", "bzip2", "xz", "image", "cab"
        }

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 256:
            return
        ent = shannon_entropy(data)

        if ent >= 7.8:
            yield Finding(
                analyzer=self.name,
                title=f"Very high entropy ({ent:.2f}/8.0)",
                severity=Severity.MEDIUM,
                category="packer",
                detail=(
                    "Whole-file entropy near maximum indicates packed, encrypted, "
                    "or compressed content. Common in obfuscated malware payloads."
                ),
                data={"entropy": round(ent, 3)},
            )
        elif ent >= 7.2:
            yield Finding(
                analyzer=self.name,
                title=f"Elevated entropy ({ent:.2f}/8.0)",
                severity=Severity.LOW,
                category="packer",
                detail="Higher-than-typical entropy; may indicate partial packing.",
                data={"entropy": round(ent, 3)},
            )
        else:
            yield Finding(
                analyzer=self.name,
                title=f"Entropy {ent:.2f}/8.0",
                severity=Severity.INFO,
                category="packer",
                data={"entropy": round(ent, 3)},
            )
