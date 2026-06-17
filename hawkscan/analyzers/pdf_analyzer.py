"""PDF analysis in the spirit of pdfid: flag active-content keywords.

Pure stdlib. Counts the high-risk PDF object types that legitimate documents
rarely need but malicious PDFs rely on to execute on open.
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# (keyword, title, severity) - presence/count is what matters.
_KEYWORDS: list[tuple[bytes, str, Severity, str]] = [
    (b"/OpenAction", "OpenAction (runs on open)", Severity.MEDIUM, "execution"),
    (b"/AA", "Additional Actions trigger", Severity.MEDIUM, "execution"),
    (b"/JavaScript", "Embedded JavaScript", Severity.HIGH, "execution"),
    (b"/JS", "Embedded JavaScript (/JS)", Severity.HIGH, "execution"),
    (b"/Launch", "Launch action (runs external program)", Severity.HIGH, "execution"),
    (b"/EmbeddedFile", "Embedded file", Severity.MEDIUM, "dropper"),
    (b"/RichMedia", "RichMedia / Flash object", Severity.MEDIUM, "execution"),
    (b"/URI", "External URI", Severity.LOW, "network"),
    (b"/SubmitForm", "SubmitForm action", Severity.LOW, "network"),
    (b"/GoToR", "Remote go-to action", Severity.LOW, "network"),
]


class PDFAnalyzer(Analyzer):
    name = "pdf"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "pdf"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        for kw, title, severity, category in _KEYWORDS:
            # Count both direct and hex-escaped (e.g. /J#61vaScript) forms.
            count = len(re.findall(re.escape(kw), data))
            if count:
                yield Finding(
                    analyzer=self.name,
                    title=f"{title} x{count}",
                    severity=severity,
                    category=category,
                    detail=f"PDF keyword {kw.decode()!r} present {count} time(s).",
                )

        # Name obfuscation via hex-escapes inside object names is a classic
        # evasion (e.g. /#4Aava#53cript). Flag if present at all.
        if re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data):
            yield Finding(
                analyzer=self.name,
                title="Hex-escaped name obfuscation",
                severity=Severity.MEDIUM,
                category="obfuscation",
                detail="PDF object names use #-hex escapes to hide keywords from "
                       "naive scanners.",
            )
