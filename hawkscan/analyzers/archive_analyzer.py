"""Archive analysis: inspect ZIP contents for risky members.

Recursing into archives fully is out of scope for v1 (and a zip-bomb risk), but
the member listing alone is a strong triage signal: an "invoice.pdf.exe" or a
double-extension inside a zip, an encrypted archive, etc.
"""

from __future__ import annotations

import zipfile
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_RISKY_EXTS = {".exe", ".scr", ".dll", ".com", ".pif", ".bat", ".cmd", ".vbs",
               ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".jar",
               ".msi", ".cpl"}
_DOUBLE_EXT = (".pdf.", ".doc.", ".xls.", ".jpg.", ".png.", ".txt.", ".invoice.")
# Unicode bidirectional-control characters abused to disguise file extensions
# (e.g. U+202E RLO turns "...gpj.exe" into a visual "...exe.jpg").
_BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮",
               "⁦", "⁧", "⁨", "⁩", "‎", "‏"}


class ArchiveAnalyzer(Analyzer):
    name = "archive"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"zip", "jar", "apk"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            # Only metadata is needed; ZipInfo objects stay valid after close,
            # so read the listing inside the context manager and release the handle.
            with zipfile.ZipFile(ctx.path) as zf:
                infos = zf.infolist()
        except Exception as exc:
            yield Finding(analyzer=self.name, title="Unreadable ZIP structure",
                          severity=Severity.LOW, category="format",
                          detail=str(exc))
            return

        encrypted = any(i.flag_bits & 0x1 for i in infos)
        if encrypted:
            yield Finding(
                analyzer=self.name,
                title="Password-protected archive",
                severity=Severity.MEDIUM,
                category="evasion",
                detail="Encrypted archives evade content scanning; common in "
                       "phishing payload delivery.",
            )

        risky = []
        files = [i for i in infos if not i.is_dir()]
        for i in infos:
            name = i.filename.lower()
            ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
            if ext in _RISKY_EXTS:
                risky.append(i.filename)
            if any(d in name for d in _DOUBLE_EXT) and ext in _RISKY_EXTS:
                yield Finding(
                    analyzer=self.name,
                    title=f"Double-extension lure: {i.filename}",
                    severity=Severity.HIGH,
                    category="masquerading",
                    detail="Member name disguises an executable as a document/image.",
                )
            # Bidi/RTL-override extension spoofing.
            if any(c in i.filename for c in _BIDI_CHARS):
                yield Finding(
                    analyzer=self.name,
                    title="Bidirectional-control character in member name",
                    severity=Severity.HIGH, category="masquerading",
                    detail="A member filename contains a Unicode RTL/bidi-override "
                           "character used to disguise the real file extension.")
            # Zip Slip / absolute path traversal in member name.
            fn = i.filename.replace("\\", "/")
            if fn.startswith("/") or fn[1:3] == ":/" or "../" in fn:
                yield Finding(
                    analyzer=self.name,
                    title=f"Path-traversal member name (Zip Slip): {i.filename}",
                    severity=Severity.HIGH, category="exploit",
                    detail="Member path escapes the extraction directory; can "
                           "overwrite arbitrary files on extraction.")

        if risky:
            # A lone executable/script member is the classic malspam wrapper.
            if len(files) == 1 and len(risky) == 1:
                yield Finding(
                    analyzer=self.name,
                    title=f"Archive wraps a single executable/script: {risky[0]}",
                    severity=Severity.HIGH, category="dropper",
                    detail="The archive's only content is an executable/script - the "
                           "typical shape of a malspam payload wrapper.")
            else:
                yield Finding(
                    analyzer=self.name,
                    title=f"{len(risky)} executable/script member(s) in archive",
                    severity=Severity.MEDIUM,
                    category="dropper",
                    detail="; ".join(risky[:8]),
                )

        # Zip-bomb heuristic: extreme compression ratio.
        total_comp = sum(i.compress_size for i in infos) or 1
        total_uncomp = sum(i.file_size for i in infos)
        bomb = total_uncomp / total_comp > 100 and total_uncomp > 50 * 1024 * 1024
        if bomb:
            yield Finding(
                analyzer=self.name,
                title=f"Extreme compression ratio ({total_uncomp // total_comp}:1)",
                severity=Severity.MEDIUM,
                category="dos",
                detail="Possible decompression bomb.",
            )

        # Recurse: extract members and re-scan each so a malicious file packed
        # inside the archive is analysed on its own. Bounded to avoid zip bombs.
        if not bomb:
            yield from self._scan_members(ctx, infos)

    def _scan_members(self, ctx, infos) -> Iterable[Finding]:
        from ..core.engine import Engine
        from ..analyzers import ALL_ANALYZERS
        from pathlib import Path

        members = [i for i in infos if not i.is_dir()
                   and 0 < i.file_size <= 16 * 1024 * 1024
                   and not (i.flag_bits & 0x1)][:10]  # skip encrypted/huge; cap 10
        if not members:
            return
        # Sub-engine without ArchiveAnalyzer to bound recursion depth to 1.
        sub = Engine(analyzers=[c for c in ALL_ANALYZERS
                                if c is not ArchiveAnalyzer])
        from ..core.findings import Verdict, Severity as Sev
        with zipfile.ZipFile(ctx.path) as zf:
            for m in members:
                try:
                    blob = zf.read(m)
                except Exception:
                    continue
                # In-memory member scan: the extracted (possibly malicious)
                # member is never written to disk, so an on-access EDR cannot
                # quarantine it and abort the scan.
                try:
                    res = sub.scan_bytes(blob, name=Path(m.filename).name)
                except Exception:
                    continue
                if res.verdict >= Verdict.SUSPICIOUS:
                    sev = (Sev.HIGH if res.verdict >= Verdict.LIKELY_MALICIOUS
                           else Sev.MEDIUM)
                    yield Finding(
                        analyzer=self.name,
                        title=f"Archived member is {res.verdict.label}: "
                              f"{m.filename}",
                        severity=sev, category="dropper",
                        detail="A file inside the archive scanned as "
                               f"{res.verdict.label}.")
