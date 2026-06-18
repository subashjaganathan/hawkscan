"""Analyzer base class and the shared per-scan context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..core.fileinfo import FileInfo
from ..core.findings import Finding


@dataclass
class AnalysisContext:
    """Everything an analyzer might need, computed once and shared.

    `content` is the full file bytes when the file is small enough to hold in
    memory; for very large files it is None and analyzers should stream from
    `info.path` instead. This avoids reading multi-GB files repeatedly.
    """

    info: FileInfo
    content: bytes | None = None
    max_in_memory: int = 64 * 1024 * 1024  # 64 MiB
    cache: dict = field(default_factory=dict)  # analyzers may memoize here

    @property
    def path(self) -> Path:
        return self.info.path

    def read_all(self) -> bytes:
        """Return full bytes, reading from disk once and caching the result so
        large files are not re-read by every analyzer."""
        if self.content is None:
            self.content = self.info.path.read_bytes()
        return self.content


class Analyzer:
    """Base class. Subclasses set `name`, implement `applies` and `analyze`."""

    name: str = "analyzer"
    #: Optional human note shown when the analyzer is skipped (missing dep).
    unavailable_reason: str | None = None

    @classmethod
    def is_available(cls) -> bool:
        """Return False if an optional dependency is missing."""
        return True

    def applies(self, ctx: AnalysisContext) -> bool:
        """Whether this analyzer is relevant to the given file."""
        raise NotImplementedError

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        """Yield Findings. May yield nothing."""
        raise NotImplementedError
