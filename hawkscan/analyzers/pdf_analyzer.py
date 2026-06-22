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

        # Decompress FlateDecode streams and inspect the decoded content: PDF
        # malware commonly hides JavaScript inside compressed object streams that
        # raw-keyword scanning cannot see.
        yield from self._scan_streams(data)

    def _scan_streams(self, data: bytes) -> Iterable[Finding]:
        import zlib
        flagged = False
        # Each "stream ... endstream" body that follows a /FlateDecode filter.
        for m in re.finditer(rb"stream\r?\n", data):
            start = m.end()
            end = data.find(b"endstream", start)
            if end == -1:
                continue
            blob = data[start:end].rstrip(b"\r\n")
            # Only attempt zlib-compressed streams (zlib header 0x78).
            if not blob[:1] == b"\x78":
                continue
            try:
                dec = zlib.decompress(blob)
            except Exception:
                continue
            low = dec.lower()
            if (b"/js" in low or b"javascript" in low or b"eval(" in low
                    or b"unescape(" in low or b"app.alert" in low
                    or b"this.exportdataobject" in low):
                yield Finding(
                    analyzer=self.name,
                    title="JavaScript inside a compressed PDF stream",
                    severity=Severity.HIGH, category="execution",
                    detail="Decompressed a FlateDecode stream and found JavaScript; "
                           "hidden from raw-keyword scanning.")
                flagged = True
            if not flagged and (b"%pdf" in low and b"this program cannot be run"
                                in low):
                yield Finding(
                    analyzer=self.name,
                    title="Embedded executable in a compressed PDF stream",
                    severity=Severity.HIGH, category="dropper",
                    detail="A decompressed stream contains an embedded PE.")
                flagged = True
            if flagged:
                return
