"""Scan orchestration: run analyzers, aggregate findings into a verdict."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import fileinfo
from .findings import Finding, Severity, Verdict, score_to_verdict


@dataclass
class ScanResult:
    info: fileinfo.FileInfo
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: Verdict = Verdict.CLEAN
    analyzers_run: list[str] = field(default_factory=list)
    analyzers_skipped: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0

    @property
    def confidence(self) -> str:
        """Rough confidence in the verdict from the strength of evidence."""
        if any(f.severity >= Severity.CRITICAL for f in self.findings):
            return "high"
        highs = sum(1 for f in self.findings if f.severity >= Severity.HIGH)
        if highs >= 2:
            return "high"
        if highs == 1 or self.score >= 45:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": {
                "path": str(self.info.path),
                "size": self.info.size,
                "type": self.info.file_type,
                "description": self.info.description,
                "extension": self.info.extension,
                "magic": self.info.magic_hex,
                "ext_mismatch": self.info.ext_mismatch,
                "md5": self.info.md5,
                "sha1": self.info.sha1,
                "sha256": self.info.sha256,
            },
            "verdict": self.verdict.label,
            "score": self.score,
            "confidence": self.confidence,
            "findings": [f.to_dict() for f in self.findings],
            "analyzers_run": self.analyzers_run,
            "analyzers_skipped": self.analyzers_skipped,
            "errors": self.errors,
            "duration_ms": round(self.duration_ms, 1),
        }


class Engine:
    def __init__(self, analyzers: list | None = None, rules_dir: Path | None = None):
        # Imported here to avoid a circular import at module load.
        from ..analyzers import ALL_ANALYZERS

        self.analyzer_classes = analyzers if analyzers is not None else ALL_ANALYZERS
        self.rules_dir = rules_dir

    def scan(self, path: str | Path) -> ScanResult:
        start = time.perf_counter()
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Not a file: {path}")

        info = fileinfo.inspect(path)
        ctx_content = None
        if info.size <= 64 * 1024 * 1024:
            ctx_content = path.read_bytes()

        from ..analyzers.base import AnalysisContext

        ctx = AnalysisContext(info=info, content=ctx_content)
        ctx.cache["rules_dir"] = self.rules_dir

        result = ScanResult(info=info)

        # An extension/type mismatch is itself a finding (masquerading).
        if info.ext_mismatch:
            result.findings.append(
                Finding(
                    analyzer="fileinfo",
                    title="File extension does not match content",
                    severity=Severity.MEDIUM,
                    category="masquerading",
                    detail=(
                        f"Extension '{info.extension}' but content is "
                        f"{info.file_type} ({info.description}). Mislabeled files "
                        "are a common delivery trick."
                    ),
                )
            )

        for cls in self.analyzer_classes:
            inst = cls()
            if not cls.is_available():
                result.analyzers_skipped[cls.name] = (
                    cls.unavailable_reason or "optional dependency not installed"
                )
                continue
            try:
                if not inst.applies(ctx):
                    continue
                produced = list(inst.analyze(ctx))
                result.findings.extend(produced)
                result.analyzers_run.append(cls.name)
            except Exception as exc:  # one analyzer must never sink the scan
                result.errors[cls.name] = f"{type(exc).__name__}: {exc}"
                result.errors[cls.name + ":trace"] = traceback.format_exc()

        result.score = sum(int(f.severity) for f in result.findings)
        result.verdict = score_to_verdict(result.score)
        result.duration_ms = (time.perf_counter() - start) * 1000
        return result
