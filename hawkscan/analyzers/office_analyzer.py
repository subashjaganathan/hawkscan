"""Microsoft Office document analysis (macros, DDE, embedded objects).

Uses `oletools` (olevba) when available for full VBA extraction. Without it,
falls back to detecting the presence of a macro stream, which is still a strong
triage signal for OOXML (.docm/.xlsm) and OLE2 documents.
"""

from __future__ import annotations

import zipfile
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

try:
    from oletools.olevba import VBA_Parser  # type: ignore
    _HAVE_OLEVBA = True
except Exception:
    _HAVE_OLEVBA = False

_AUTO_EXEC = ("AutoOpen", "Auto_Open", "AutoClose", "AutoExec", "Document_Open",
              "Workbook_Open", "Document_Close")
_VBA_RED_FLAGS = ("Shell", "WScript.Shell", "CreateObject", "powershell",
                  "URLDownloadToFile", "WinHttp", "MSXML2.XMLHTTP", "Environ",
                  "GetObject", "VirtualAlloc", "CallByName", "ExecuteExcel4Macro")


class OfficeAnalyzer(Analyzer):
    name = "office"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"office-ooxml", "ole"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        if _HAVE_OLEVBA:
            yield from self._analyze_olevba(ctx)
        else:
            yield from self._analyze_fallback(ctx)

    def _analyze_olevba(self, ctx: AnalysisContext) -> Iterable[Finding]:
        parser = VBA_Parser(str(ctx.path), data=ctx.read_all())
        if not parser.detect_vba_macros():
            yield Finding(analyzer=self.name, title="No VBA macros present",
                          severity=Severity.INFO, category="macro")
            parser.close()
            return

        all_code = []
        for _, _, _, code in parser.extract_macros():
            if code:
                all_code.append(code)
        code_blob = "\n".join(all_code)
        parser.close()

        yield Finding(
            analyzer=self.name,
            title="Document contains VBA macros",
            severity=Severity.MEDIUM,
            category="macro",
            detail="Macro-enabled documents are a primary malware delivery vector.",
        )
        autos = [k for k in _AUTO_EXEC if k.lower() in code_blob.lower()]
        if autos:
            yield Finding(
                analyzer=self.name,
                title=f"Auto-executing macro ({', '.join(autos)})",
                severity=Severity.HIGH,
                category="macro",
                detail="Macro runs automatically on open/close without user action.",
            )
        flags = [k for k in _VBA_RED_FLAGS if k.lower() in code_blob.lower()]
        if flags:
            yield Finding(
                analyzer=self.name,
                title=f"Suspicious macro API calls: {', '.join(flags[:6])}",
                severity=Severity.HIGH,
                category="execution",
                detail="Macro invokes shell/download/process APIs.",
            )

    def _analyze_fallback(self, ctx: AnalysisContext) -> Iterable[Finding]:
        has_macro = False
        if ctx.info.file_type == "office-ooxml":
            try:
                with zipfile.ZipFile(ctx.path) as zf:
                    names = zf.namelist()
                has_macro = any("vbaProject.bin" in n for n in names)
            except Exception:
                pass
        else:  # OLE2: look for the macro storage marker in raw bytes.
            data = ctx.read_all()
            has_macro = b"VBA" in data and (b"_VBA_PROJECT" in data or b"\x00A\x00t\x00t\x00r\x00i\x00b" in data)

        if has_macro:
            yield Finding(
                analyzer=self.name,
                title="Document contains a VBA macro project",
                severity=Severity.MEDIUM,
                category="macro",
                detail="Macro stream detected. Install 'oletools' to extract and "
                       "score the macro source.",
            )
        else:
            yield Finding(analyzer=self.name, title="No macro stream detected",
                          severity=Severity.INFO, category="macro")
