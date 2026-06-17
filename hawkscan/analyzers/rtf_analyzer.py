"""RTF document analysis.

RTF is a common malware-delivery format: it can embed OLE objects and exploit
payloads (notably the Equation Editor CVE-2017-11882 / CVE-2018-0802 chain).
This analyzer flags the control words and embedded-object markers that legitimate
documents rarely need.
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# (regex, title, severity, category)
_INDICATORS: list[tuple[re.Pattern, str, Severity, str]] = [
    (re.compile(rb"\\objdata", re.I),
     "Embedded OLE object data (\\objdata)", Severity.MEDIUM, "embedded-object"),
    (re.compile(rb"\\objupdate", re.I),
     "Auto-updating OLE object (\\objupdate)", Severity.HIGH, "execution"),
    (re.compile(rb"\\objclass\s*Equation", re.I),
     "Equation Editor object (CVE-2017-11882 / CVE-2018-0802)", Severity.HIGH, "exploit"),
    (re.compile(rb"\\objclass\s*OLE2Link", re.I),
     "OLE2Link object (CVE-2017-0199)", Severity.HIGH, "exploit"),
    (re.compile(rb"\\objclass\s*Package", re.I),
     "Packager object (drops/executes embedded file)", Severity.HIGH, "dropper"),
    (re.compile(rb"\\datastore", re.I),
     "Embedded data store (\\datastore)", Severity.MEDIUM, "embedded-object"),
    (re.compile(rb"\\objocx", re.I),
     "Embedded ActiveX/OCX control", Severity.MEDIUM, "embedded-object"),
    (re.compile(rb"mscomctl|MSComctlLib", re.I),
     "MSComctl control reference (common exploit carrier)", Severity.MEDIUM, "exploit"),
]

# A long hex stream after \objdata carries the actual OLE payload.
_HEX_BLOB = re.compile(rb"[0-9A-Fa-f]{512,}")


class RTFAnalyzer(Analyzer):
    name = "rtf"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "rtf"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()

        seen: set[str] = set()
        for pattern, title, severity, category in _INDICATORS:
            if pattern.search(data) and title not in seen:
                seen.add(title)
                yield Finding(analyzer=self.name, title=title, severity=severity,
                              category=category)

        # Large embedded hex blob = likely an OLE payload. Decode the leading
        # bytes to spot an embedded PE ("d0cf11e0" OLE header or "4d5a" MZ).
        m = _HEX_BLOB.search(data)
        if m:
            head = m.group()[:16].lower()
            note = ""
            if head.startswith(b"d0cf11e0"):
                note = " (OLE compound document header)"
            elif head.startswith(b"4d5a"):
                note = " (embedded PE / MZ header)"
            yield Finding(
                analyzer=self.name,
                title=f"Large embedded hex object{note}",
                severity=Severity.HIGH if note else Severity.LOW,
                category="embedded-object",
                detail=f"{len(m.group())} hex chars; decodes to a binary payload.",
            )
