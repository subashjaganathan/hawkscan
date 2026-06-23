"""Binary runtime/compiler profiling.

Identifies the toolchain a binary was produced with - Go, .NET/managed, Rust,
Nim, PyInstaller - from characteristic strings. Knowing the runtime focuses
later analysis (e.g. Go binaries need symbol recovery; .NET needs IL tooling)
and some runtimes are themselves a mild signal for commodity malware packers.
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_GO_VERSION = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
# Go module build-info lines are tab-delimited: path/mod/dep/build <value>.
_GO_BUILDINFO = re.compile(rb"\b(path|mod|dep|build)\t([^\t\n\x00]{1,200})")

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
        go_detected = False
        for label, markers, note in _RUNTIMES:
            if any(m in blob for m in markers):
                go_detected = go_detected or label == "Go"
                yield Finding(
                    analyzer=self.name,
                    title=f"{label} runtime detected",
                    severity=Severity.INFO,
                    category="runtime",
                    detail=note,
                    data={"runtime": label},
                )

        # Deeper Go profiling: recover build metadata (module path, version,
        # dependencies) from the embedded build-info, useful for attribution.
        if go_detected or b"Go buildinf:" in ctx.read_all()[:64] or "go1." in blob:
            yield from self._go_buildinfo(ctx.read_all())

    def _go_buildinfo(self, data: bytes) -> Iterable[Finding]:
        ver = _GO_VERSION.search(data)
        version = ver.group().decode("ascii", "ignore") if ver else ""
        path = ""
        deps: list[str] = []
        for m in _GO_BUILDINFO.finditer(data):
            kind = m.group(1).decode("ascii", "ignore")
            val = m.group(2).decode("latin1", "ignore").strip()
            if kind == "path" and not path:
                path = val
            elif kind in ("dep", "mod") and val:
                deps.append(val.split("\t")[0])
        if not (version or path):
            return
        detail = []
        if version:
            detail.append(f"version {version}")
        if path:
            detail.append(f"module {path}")
        if deps:
            detail.append(f"{len(set(deps))} dependenc(y/ies)")
        yield Finding(
            analyzer=self.name,
            title=f"Go build info: {path or version or 'present'}",
            severity=Severity.INFO,
            category="attribution",
            detail="; ".join(detail),
            data={"go_version": version, "go_module": path,
                  "go_deps": sorted(set(deps))[:30]},
        )
