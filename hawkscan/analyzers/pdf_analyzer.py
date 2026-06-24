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
    (b"/XFA", "XFA form (can carry scripts)", Severity.LOW, "execution"),
]

# JavaScript APIs tied to well-known Adobe Reader exploits; their presence in a
# PDF's script is a strong indicator of an exploit document.
_EXPLOIT_APIS: list[tuple[str, str]] = [
    ("util.printf", "CVE-2008-2992 (util.printf stack overflow)"),
    ("collab.collectemailinfo", "CVE-2007-5659 (collectEmailInfo)"),
    ("collab.geticon", "CVE-2009-0927 (Collab.getIcon)"),
    ("geticon", "CVE-2009-0927 (Collab.getIcon)"),
    ("media.newplayer", "CVE-2009-4324 (media.newPlayer use-after-free)"),
    ("newplayer", "CVE-2009-4324 (media.newPlayer use-after-free)"),
    ("spell.customdictionaryopen", "CVE-2009-1493 (customDictionaryOpen)"),
    ("syncannotscan", "CVE-2009-1492 (syncAnnotScan)"),
    ("this.exportdataobject", "Embedded-file drop/launch (exportDataObject)"),
]
_URL_RE = re.compile(rb"https?://[^\s\)\"'<>\\]{4,300}", re.I)


class PDFAnalyzer(Analyzer):
    name = "pdf"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "pdf"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        has_js = has_openaction = False
        for kw, title, severity, category in _KEYWORDS:
            # Count both direct and hex-escaped (e.g. /J#61vaScript) forms.
            count = len(re.findall(re.escape(kw), data))
            if count:
                if kw in (b"/JavaScript", b"/JS"):
                    has_js = True
                if kw in (b"/OpenAction", b"/AA"):
                    has_openaction = True
                yield Finding(
                    analyzer=self.name,
                    title=f"{title} x{count}",
                    severity=severity,
                    category=category,
                    detail=f"PDF keyword {kw.decode()!r} present {count} time(s).",
                )

        # OpenAction + JavaScript = script runs automatically on open.
        if has_js and has_openaction:
            yield Finding(
                analyzer=self.name, title="Auto-executing JavaScript on open",
                severity=Severity.HIGH, category="execution",
                detail="An OpenAction/AA trigger combined with embedded JavaScript "
                       "runs the script the moment the document is opened.")

        if re.search(rb"/Encrypt\b", data):
            yield Finding(
                analyzer=self.name, title="Encrypted PDF",
                severity=Severity.LOW, category="evasion",
                detail="Encrypted PDFs can hide content from scanners; combined "
                       "with active content this is a common evasion.")

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

        yield from self._extract_iocs(data)

        # Gather JavaScript from literal /JS strings and decompressed streams,
        # then deobfuscate and inspect it for exploit APIs / heap spray / IOCs.
        js = self._collect_js(data)
        if js:
            yield from self._analyze_js(js)

        # Embedded-executable inside a compressed stream (dropper).
        yield from self._scan_streams(data)

    def _decompressed_streams(self, data: bytes):
        """Yield each FlateDecode (zlib) stream body, decompressed."""
        import zlib
        for m in re.finditer(rb"stream\r?\n", data):
            start = m.end()
            end = data.find(b"endstream", start)
            if end == -1:
                continue
            blob = data[start:end].rstrip(b"\r\n")
            if blob[:1] != b"\x78":  # zlib header
                continue
            try:
                yield zlib.decompress(blob)
            except Exception:
                continue

    def _collect_js(self, data: bytes) -> str:
        """Pull JavaScript from literal /JS (...) strings and from decompressed
        streams that look like script."""
        parts: list[str] = []
        for m in re.finditer(rb"/(?:JS|JavaScript)\s*\(((?:\\.|[^()]|\([^)]*\))*)\)",
                             data, re.S):
            parts.append(m.group(1).decode("latin1", "ignore"))
        for dec in self._decompressed_streams(data):
            low = dec.lower()
            if (b"function" in low or b"var " in low or b"eval(" in low
                    or b"unescape(" in low or b"app." in low
                    or b"this.export" in low or b"=app" in low):
                parts.append(dec.decode("latin1", "ignore"))
            if len(parts) >= 12:
                break
        return "\n".join(parts)

    def _analyze_js(self, js: str) -> Iterable[Finding]:
        from .deobfuscate import DeobAnalyzer
        deob = DeobAnalyzer._script_deob(js.encode("latin1", "ignore"))
        text = js + "\n" + (deob.decode("latin1", "ignore") if deob else "")
        low = text.lower()

        yield Finding(
            analyzer=self.name, title="Embedded JavaScript extracted",
            severity=Severity.HIGH, category="execution",
            detail=f"Recovered {len(js):,} chars of PDF JavaScript for inspection.")

        for api, cve in _EXPLOIT_APIS:
            if api in low:
                yield Finding(
                    analyzer=self.name,
                    title=f"PDF exploit API: {api}",
                    severity=Severity.HIGH, category="exploit",
                    detail=f"JavaScript calls {api}; associated with {cve}.")

        # Heap spray: unescape() feeding %u-encoded shellcode, repeated to fill
        # the heap. The combination (not unescape alone) is the signal.
        if "unescape" in low and len(re.findall(r"%u[0-9a-f]{4}", low)) >= 8:
            yield Finding(
                analyzer=self.name, title="Heap-spray shellcode pattern",
                severity=Severity.HIGH, category="exploit",
                detail="unescape() with many %u-encoded units; classic heap-spray "
                       "to stage shellcode before triggering a memory-corruption bug.")

        urls = sorted({u.decode("latin1", "ignore")
                       for u in _URL_RE.findall(text.encode("latin1", "ignore"))})[:15]
        if urls:
            yield Finding(
                analyzer=self.name, title="C2/payload URL in PDF JavaScript",
                severity=Severity.HIGH, category="network",
                detail="Recovered URL(s): " + ", ".join(urls),
                data={"urls": urls})

    def _extract_iocs(self, data: bytes) -> Iterable[Finding]:
        # /Launch target (external program/command run by the document).
        for m in re.finditer(rb"/Launch\b[^>]{0,400}", data, re.S):
            seg = m.group(0)
            fm = re.search(rb"/(?:F|Win)\s*(?:\(([^)]{1,300})\)|<<[^>]*?/F\s*\(([^)]{1,300})\))",
                           seg)
            target = ""
            if fm:
                target = (fm.group(1) or fm.group(2) or b"").decode("latin1", "ignore")
            if target:
                yield Finding(
                    analyzer=self.name,
                    title=f"Launch action target: {target[:120]}",
                    severity=Severity.HIGH, category="execution",
                    detail="The /Launch action runs an external program/command.",
                    data={"launch_target": target})
                break

    def _scan_streams(self, data: bytes) -> Iterable[Finding]:
        for dec in self._decompressed_streams(data):
            low = dec.lower()
            if b"%pdf" in low and b"this program cannot be run" in low:
                yield Finding(
                    analyzer=self.name,
                    title="Embedded executable in a compressed PDF stream",
                    severity=Severity.HIGH, category="dropper",
                    detail="A decompressed stream contains an embedded PE.")
                return
