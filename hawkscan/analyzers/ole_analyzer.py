"""OLE compound-document and Outlook .msg analysis.

Walks the streams of legacy OLE files (.doc/.xls/.msi and Outlook .msg) using
the optional `olefile` library. For .msg it extracts the subject, transport
headers (for SPF/DKIM/DMARC failure checks) and attachments (flagging risky or
executable ones). For other OLE files it flags embedded-object streams that
indicate a dropped/launched payload. Degrades to a note if olefile is absent.
"""

from __future__ import annotations

import io
import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

try:
    import olefile  # type: ignore
    _HAVE_OLEFILE = True
except Exception:
    _HAVE_OLEFILE = False

_RISKY_EXTS = (".exe", ".scr", ".com", ".js", ".vbs", ".bat", ".cmd", ".ps1",
               ".hta", ".jar", ".lnk", ".dll", ".wsf")
# OLE stream names that carry embedded/launchable objects.
_EMBED_STREAMS = ("ole10native", "package", "equation native", "\x01ole")


class OleAnalyzer(Analyzer):
    name = "ole"

    def applies(self, ctx: AnalysisContext) -> bool:
        return _HAVE_OLEFILE and ctx.info.file_type == "ole"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            ole = olefile.OleFileIO(io.BytesIO(ctx.read_all()))
        except Exception as exc:
            yield Finding(analyzer=self.name, title="Unreadable OLE structure",
                          severity=Severity.LOW, category="format", detail=str(exc))
            return
        try:
            streams = ["/".join(p) for p in ole.listdir()]
            is_msg = any("__substg1.0" in s for s in streams) or \
                ctx.info.extension == ".msg"
            if is_msg:
                yield from self._analyze_msg(ole, streams)
            else:
                yield from self._analyze_ole(ole, streams)
        finally:
            ole.close()

    # ---- Outlook .msg ---------------------------------------------------
    def _read(self, ole, name: str) -> bytes:
        try:
            return ole.openstream(name).read()
        except Exception:
            return b""

    def _analyze_msg(self, ole, streams) -> Iterable[Finding]:
        subject = self._read(ole, "__substg1.0_0037001F").decode("utf-16le", "ignore")
        yield Finding(analyzer=self.name, title="Outlook .msg email",
                      severity=Severity.INFO, category="format",
                      detail=f"Subject: {subject[:100]!r}" if subject else "")

        headers = self._read(ole, "__substg1.0_007D001F").decode("utf-16le", "ignore").lower()
        for token, label in (("spf=fail", "SPF"), ("dkim=fail", "DKIM"),
                             ("dmarc=fail", "DMARC")):
            if token in headers:
                yield Finding(analyzer=self.name,
                              title=f"{label} authentication failed (.msg)",
                              severity=Severity.MEDIUM, category="spoofing")

        # Attachment long filenames live in __attach storages as 3707001F.
        for s in streams:
            if "__attach" in s and s.endswith(("3707001F", "3704001F")):
                fn = self._read(ole, s).decode("utf-16le", "ignore")
                low = fn.lower()
                if any(low.endswith(e) for e in _RISKY_EXTS):
                    yield Finding(
                        analyzer=self.name,
                        title=f"Risky email attachment: {fn}",
                        severity=Severity.HIGH, category="dropper",
                        detail="Executable/script attachment in the message.")
            if "__attach" in s and s.endswith("37010102"):  # attachment bytes
                head = self._read(ole, s)[:4]
                if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
                    yield Finding(
                        analyzer=self.name, title="Executable attachment payload",
                        severity=Severity.HIGH, category="dropper",
                        detail="An attachment's bytes start with an executable header.")

    # ---- generic OLE ----------------------------------------------------
    def _analyze_ole(self, ole, streams) -> Iterable[Finding]:
        yield Finding(analyzer=self.name,
                      title=f"OLE compound file ({len(streams)} streams)",
                      severity=Severity.INFO, category="format")
        low = [s.lower() for s in streams]
        for marker in _EMBED_STREAMS:
            if any(marker in s for s in low):
                sev = Severity.HIGH if marker in ("ole10native", "package") \
                    else Severity.MEDIUM
                yield Finding(
                    analyzer=self.name,
                    title=f"Embedded object stream ({marker})",
                    severity=sev, category="dropper",
                    detail="OLE stream carries an embedded/launchable object.")

        # Ole10Native packages store the original filename/path of the embedded
        # object; recovering it reveals the dropped payload's name and type.
        for s in streams:
            if s.lower().endswith("ole10native") or s.lower() == "\x01ole10native":
                yield from self._ole10native(self._read(ole, s))
                break
        if any("macros" in s or "vba" in s for s in low):
            yield Finding(analyzer=self.name, title="VBA macro storage present",
                          severity=Severity.MEDIUM, category="macro",
                          detail="Legacy document contains a macro project.")

    def _ole10native(self, data: bytes) -> Iterable[Finding]:
        # Layout: DWORD totalsize, WORD flags, then NUL-terminated ANSI label and
        # source path, a DWORD, NUL-terminated temp path, then DWORD payload size
        # + payload. We only need the label/path to name the dropped object.
        if len(data) < 8:
            return
        try:
            parts = data[6:].split(b"\x00")
            label = parts[0].decode("latin1", "ignore") if parts else ""
        except Exception:
            label = ""
        if not label:
            return
        low = label.lower()
        risky = any(low.endswith(e) for e in _RISKY_EXTS)
        yield Finding(
            analyzer=self.name,
            title=f"Embedded packaged file: {label}",
            severity=Severity.HIGH if risky else Severity.MEDIUM,
            category="dropper",
            detail=("Embedded object is an executable/script - double-click runs it."
                    if risky else "OLE Package embeds a file object."),
            data={"embedded_name": label})
