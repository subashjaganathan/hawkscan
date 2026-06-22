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

        if risky:
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
        import tempfile
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
        tmp = Path(tempfile.mkdtemp(prefix="hawkscan_arc_"))
        try:
            with zipfile.ZipFile(ctx.path) as zf:
                for m in members:
                    try:
                        blob = zf.read(m)
                    except Exception:
                        continue
                    out = tmp / Path(m.filename).name
                    try:
                        out.write_bytes(blob)
                        res = sub.scan(out)
                    except Exception:
                        continue
                    finally:
                        out.unlink(missing_ok=True)
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
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
