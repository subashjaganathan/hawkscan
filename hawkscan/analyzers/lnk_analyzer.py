"""Windows shortcut (.lnk) analysis.

Malicious LNK files are a common delivery vector: a shortcut whose target is a
command interpreter with an embedded, often obfuscated, command line. This parses
the Shell Link header flags and recovers the embedded strings (command-line
arguments, target paths) to surface the hidden command.
"""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from .strings_analyzer import extract_strings
from ..core.findings import Finding, Severity

# LinkFlags bits we care about.
_HAS_ARGUMENTS = 0x00000020
_HAS_ICON = 0x00000040

_SUSPECT = ("powershell", "cmd.exe", "cmd /c", "/c ", "mshta", "wscript",
            "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin",
            "-enc", "-w hidden", "-nop", "iex", "downloadstring", "http://",
            "https://", "frombase64string", "curl", "%comspec%")


class LnkAnalyzer(Analyzer):
    name = "lnk"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "lnk"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 76:
            return
        try:
            link_flags = struct.unpack_from("<I", data, 20)[0]
        except struct.error:
            return

        has_args = bool(link_flags & _HAS_ARGUMENTS)
        yield Finding(analyzer=self.name, title="Windows shortcut (LNK)",
                      severity=Severity.INFO, category="format",
                      detail=f"LinkFlags=0x{link_flags:08x}"
                             f"{', has arguments' if has_args else ''}")

        # The command line / target live as strings after the header.
        ascii_s, _ = extract_strings(data, min_len=4)
        blob = "\n".join(ascii_s).lower()
        hits = sorted({t for t in _SUSPECT if t in blob})

        if hits:
            sev = (Severity.HIGH if any(h in hits for h in
                   ("powershell", "mshta", "iex", "downloadstring", "-enc",
                    "frombase64string")) else Severity.MEDIUM)
            yield Finding(
                analyzer=self.name,
                title="Shortcut launches a command interpreter / download",
                severity=sev, category="execution",
                detail="Embedded command indicators: " + ", ".join(hits[:8]),
            )
        elif has_args:
            yield Finding(
                analyzer=self.name,
                title="Shortcut carries command-line arguments",
                severity=Severity.LOW, category="execution",
                detail="LNK targets are usually plain paths; arguments warrant a look.",
            )
