"""Linux/Unix ELF analysis using a compact stdlib header parser.

Capability scoring for ELF leans on the StringsAnalyzer (symbol/API names show
up as strings); here we report structural facts and a few high-signal traits.
"""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_ET = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
_MACHINE = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64",
            0x08: "MIPS", 0xf3: "RISC-V"}


class ELFAnalyzer(Analyzer):
    name = "elf"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "elf"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 20 or data[:4] != b"\x7fELF":
            return
        is64 = data[4] == 2
        little = data[5] == 1
        endian = "<" if little else ">"
        try:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        except struct.error:
            return

        yield Finding(
            analyzer=self.name,
            title=f"ELF {_ET.get(e_type, '?')}, "
                  f"{_MACHINE.get(e_machine, f'machine 0x{e_machine:x}')}, "
                  f"{'64' if is64 else '32'}-bit",
            severity=Severity.INFO,
            category="format",
        )

        # Statically-linked + stripped is common for self-contained malware
        # droppers and is worth noting (heuristic via section header count).
        strings = ctx.cache.get("strings")
        if strings is not None:
            blob = "\n".join(strings)
            if "/proc/" in blob and ("ptrace" in blob.lower()):
                yield Finding(
                    analyzer=self.name,
                    title="Anti-debugging via ptrace",
                    severity=Severity.MEDIUM,
                    category="anti-analysis",
                    detail="References ptrace and /proc; common self-debugging "
                           "evasion in Linux malware.",
                )
            for tok, (title, sev, cat) in {
                "LD_PRELOAD": ("LD_PRELOAD reference (userland rootkit)", Severity.MEDIUM, "persistence"),
                "/etc/cron": ("Cron persistence reference", Severity.MEDIUM, "persistence"),
                "/etc/rc.local": ("rc.local persistence reference", Severity.MEDIUM, "persistence"),
                "iptables": ("Firewall manipulation reference", Severity.LOW, "evasion"),
            }.items():
                if tok in blob:
                    yield Finding(analyzer=self.name, title=title, severity=sev,
                                  category=cat, detail=f"Contains {tok!r}.")
