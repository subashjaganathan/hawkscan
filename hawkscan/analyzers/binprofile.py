"""Binary runtime/compiler profiling.

Identifies the toolchain a binary was produced with - Go, .NET/managed, Rust,
Nim, PyInstaller - from characteristic strings. Knowing the runtime focuses
later analysis (e.g. Go binaries need symbol recovery; .NET needs IL tooling)
and some runtimes are themselves a mild signal for commodity malware packers.
"""

from __future__ import annotations

from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# (label, marker tokens, note). Presence of any marker flags the runtime.
_RUNTIMES: list[tuple[str, tuple[str, ...], str]] = [
    ("Go", ("Go build ID:", "Go buildinf:", "go1.", "runtime.goexit",
            "/usr/local/go/src"),
     "Go-compiled binary. Symbols are often stripped; function names live in "
     "the pclntab."),
    (".NET / managed", ("mscoree.dll", "_CorExeMain", "mscorlib", "#Strings",
                        "<Module>"),
     ".NET managed assembly. IL can be decompiled (dnSpy/ILSpy)."),
    ("Rust", ("rustc", "cargo", "/rustc/", "rust_panic", "core::panicking"),
     "Rust-compiled binary."),
    ("Nim", ("@m..@s", "nim_program_result", "stdlib_system.nim"),
     "Nim-compiled binary (popular in recent loaders)."),
    ("PyInstaller", ("pyi-", "PyInstaller", "_MEIPASS", "python3"),
     "Python bundled with PyInstaller; the embedded .pyc can be extracted."),
    ("AutoIt", ("AU3!", "AutoIt v3", "This is a third-party compiled AutoIt"),
     "AutoIt-compiled script; commonly used by commodity malware."),
]


class BinProfileAnalyzer(Analyzer):
    name = "binprofile"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"pe", "elf", "macho"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        blob = "\n".join(ctx.cache.get("strings") or [])
        if not blob:
            return
        for label, markers, note in _RUNTIMES:
            if any(m in blob for m in markers):
                yield Finding(
                    analyzer=self.name,
                    title=f"{label} runtime detected",
                    severity=Severity.INFO,
                    category="runtime",
                    detail=note,
                    data={"runtime": label},
                )
