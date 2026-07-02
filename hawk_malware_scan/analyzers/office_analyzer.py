"""Microsoft Office document analysis (macros, DDE, template injection, ...).

Two complementary passes:

  1. OOXML structural analysis (stdlib zipfile, no deps): remote template
     injection and external OLE-object relationships (T1221), DDE/DDEAUTO field
     execution (T1559.002), Excel 4.0 / XLM macro sheets, and embedded OLE
     objects - none of which require the macro source.
  2. VBA macro analysis via `oletools` (olevba) when available: categorised
     keyword detection (auto-exec / suspicious / IOC / obfuscation), VBA
     stomping, and recovered IOCs. Falls back to macro-presence detection.
"""

from __future__ import annotations

import re
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

_URL_RE = re.compile(r"https?://[^\s\"'<>)\\]{4,300}", re.I)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Relationship element in an OOXML *.rels part.
_REL_RE = re.compile(rb"<Relationship\b[^>]*?/?>", re.I)
_ATTR_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')
# Relationship Types that pull/execute remote or embedded content (not the
# benign hyperlink/image/styles relationships).
_DANGEROUS_REL = ("attachedtemplate", "oleobject", "frame", "subdocument",
                  "externallinkpath", "externallink")


class OfficeAnalyzer(Analyzer):
    name = "office"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"office-ooxml", "ole", "onenote"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        if ctx.info.file_type == "onenote":
            yield from self._analyze_onenote(ctx)
            return

        if ctx.info.file_type == "ole":
            data = ctx.read_all()
            if b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c" in data \
                    or b"EncryptedPackage" in data:
                yield Finding(
                    analyzer=self.name,
                    title="Encrypted/password-protected Office document",
                    severity=Severity.MEDIUM, category="evasion",
                    detail="Contains an EncryptedPackage stream; content cannot be "
                           "scanned and is often used to bypass mail/AV filtering.")
            # DDE field execution survives in the raw OLE document stream.
            if re.search(rb"DDEAUTO|DDE\s", data, re.I):
                yield self._dde_finding()

        if ctx.info.file_type == "office-ooxml":
            yield from self._analyze_ooxml_structure(ctx)

        if _HAVE_OLEVBA:
            yield from self._analyze_olevba(ctx)
        else:
            yield from self._analyze_fallback(ctx)

    # ---- OOXML structural analysis (no macro source needed) -------------
    def _analyze_ooxml_structure(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            with zipfile.ZipFile(ctx.path) as zf:
                names = zf.namelist()
                rels_parts = [n for n in names if n.endswith(".rels")]
                dde_seen = False
                # 1) external/dangerous relationships (template injection etc.)
                for rp in rels_parts:
                    try:
                        blob = zf.read(rp)
                    except Exception:
                        continue
                    for rel in _REL_RE.findall(blob):
                        attrs = {k.decode().lower(): v.decode("latin1", "ignore")
                                 for k, v in _ATTR_RE.findall(rel)}
                        if attrs.get("targetmode", "").lower() != "external":
                            continue
                        rtype = attrs.get("type", "").lower()
                        target = attrs.get("target", "")
                        kind = next((d for d in _DANGEROUS_REL if d in rtype), None)
                        if kind == "attachedtemplate":
                            yield Finding(
                                analyzer=self.name,
                                title="Remote template injection",
                                severity=Severity.HIGH, category="execution",
                                detail=f"External attached-template relationship pulls "
                                       f"a remote document: {target[:200]}. "
                                       "ATT&CK: T1221.",
                                data={"urls": _URL_RE.findall(target)})
                        elif kind:
                            yield Finding(
                                analyzer=self.name,
                                title=f"External {kind} relationship",
                                severity=Severity.HIGH, category="dropper",
                                detail=f"Document references external content "
                                       f"({rtype.rsplit('/', 1)[-1]}): {target[:200]}.",
                                data={"urls": _URL_RE.findall(target)})

                # 2) DDE field execution inside the document parts
                if not dde_seen:
                    for n in names:
                        if not n.endswith(".xml"):
                            continue
                        try:
                            if re.search(rb"DDEAUTO|ddeauto", zf.read(n)):
                                yield self._dde_finding()
                                dde_seen = True
                                break
                        except Exception:
                            continue

                # 3) Excel 4.0 / XLM macro sheets
                if any("macrosheet" in n.lower() for n in names):
                    yield Finding(
                        analyzer=self.name,
                        title="Excel 4.0 (XLM) macro sheet present",
                        severity=Severity.HIGH, category="macro",
                        detail="Legacy XLM macro sheets execute formulas on open and "
                               "are heavily abused to bypass VBA-focused defenses.")

                # 4) embedded OLE objects (potential dropped payload)
                embeds = [n for n in names if "/embeddings/" in n.lower()]
                if embeds:
                    payload = False
                    for n in embeds[:8]:
                        try:
                            head = zf.read(n)[:8]
                        except Exception:
                            continue
                        if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or \
                                head[:4] == b"\xd0\xcf\x11\xe0":
                            payload = True
                    yield Finding(
                        analyzer=self.name,
                        title=f"Embedded OLE object(s) ({len(embeds)})",
                        severity=Severity.HIGH if payload else Severity.MEDIUM,
                        category="dropper",
                        detail="Document embeds OLE object(s)"
                               + (" containing an executable/OLE payload."
                                  if payload else "; a common delivery vector."))
        except Exception:
            return

    def _dde_finding(self) -> Finding:
        return Finding(
            analyzer=self.name, title="DDE/DDEAUTO field execution",
            severity=Severity.HIGH, category="execution",
            detail="Document uses a DDE field to launch an external command "
                   "without macros. ATT&CK: T1559.002.")

    # ---- OneNote --------------------------------------------------------
    def _analyze_onenote(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        yield Finding(analyzer=self.name, title="OneNote document",
                      severity=Severity.INFO, category="format")
        if b"\xe7\x16\xe3\xbd\x65\x26\x11\x45" in data:
            yield Finding(
                analyzer=self.name,
                title="OneNote embedded file object(s)",
                severity=Severity.MEDIUM, category="dropper",
                detail="Contains FileDataStoreObject regions; OneNote attachments "
                       "are a common delivery vector for embedded executables/scripts.")

    # ---- VBA via olevba -------------------------------------------------
    def _analyze_olevba(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            parser = VBA_Parser(str(ctx.path), data=ctx.read_all())
        except Exception:
            yield from self._analyze_fallback(ctx)
            return
        try:
            if not parser.detect_vba_macros():
                yield Finding(analyzer=self.name, title="No VBA macros present",
                              severity=Severity.INFO, category="macro")
                return

            all_code = []
            for _, _, _, code in parser.extract_macros():
                if code:
                    all_code.append(code)
            code_blob = "\n".join(all_code)

            yield Finding(
                analyzer=self.name, title="Document contains VBA macros",
                severity=Severity.MEDIUM, category="macro",
                detail="Macro-enabled documents are a primary malware delivery vector.")

            # Rich categorised analysis from olevba.
            autoexec: list[str] = []
            suspicious: list[str] = []
            iocs: list[str] = []
            obfuscated = False
            try:
                results = parser.analyze_macros(show_decoded_strings=True) or []
            except Exception:
                results = []
            for kw_type, keyword, _desc in results:
                t = str(kw_type).lower()
                if "autoexec" in t:
                    autoexec.append(str(keyword))
                elif "ioc" in t:
                    iocs.append(str(keyword))
                elif "suspicious" in t:
                    suspicious.append(str(keyword))
                elif any(x in t for x in ("base64", "hex", "dridex", "obfusc")):
                    obfuscated = True

            # Recover IOCs from the (deobfuscated) macro source as well.
            urls = sorted(set(_URL_RE.findall(code_blob)
                              + [i for i in iocs if i.lower().startswith("http")]))[:15]
            ips = sorted({ip for ip in _IP_RE.findall(code_blob)
                          if not ip.startswith(("10.", "127.", "192.168.", "0."))})[:15]

            autos = autoexec or [k for k in _AUTO_EXEC if k.lower() in code_blob.lower()]
            if autos:
                yield Finding(
                    analyzer=self.name,
                    title=f"Auto-executing macro ({', '.join(sorted(set(autos))[:5])})",
                    severity=Severity.HIGH, category="macro",
                    detail="Macro runs automatically on open/close without user action.")

            flags = suspicious or [k for k in _VBA_RED_FLAGS
                                   if k.lower() in code_blob.lower()]
            if flags:
                detail = "Macro invokes shell/download/process APIs."
                if urls or ips:
                    detail += " | IOCs: " + ", ".join(urls + ips)
                yield Finding(
                    analyzer=self.name,
                    title=f"Suspicious macro behaviour: {', '.join(sorted(set(flags))[:6])}",
                    severity=Severity.HIGH, category="execution",
                    detail=detail, data={"urls": urls, "ips": ips})

            if obfuscated:
                yield Finding(
                    analyzer=self.name, title="Obfuscated macro strings",
                    severity=Severity.MEDIUM, category="obfuscation",
                    detail="Macro hides strings via Base64/Hex/Dridex-style encoding.")

            try:
                if parser.detect_vba_stomping():
                    yield Finding(
                        analyzer=self.name, title="VBA stomping detected",
                        severity=Severity.HIGH, category="evasion",
                        detail="Compiled p-code is present but the VBA source was "
                               "stripped/mismatched; defeats source-only AV. "
                               "ATT&CK: T1564.007.")
            except Exception:
                pass
        finally:
            try:
                parser.close()
            except Exception:
                pass

    def _analyze_fallback(self, ctx: AnalysisContext) -> Iterable[Finding]:
        has_macro = False
        if ctx.info.file_type == "office-ooxml":
            try:
                with zipfile.ZipFile(ctx.path) as zf:
                    names = zf.namelist()
                has_macro = any("vbaProject.bin" in n for n in names)
            except Exception:
                pass
        else:
            data = ctx.read_all()
            has_macro = b"VBA" in data and (b"_VBA_PROJECT" in data or b"\x00A\x00t\x00t\x00r\x00i\x00b" in data)

        if has_macro:
            yield Finding(
                analyzer=self.name,
                title="Document contains a VBA macro project",
                severity=Severity.MEDIUM, category="macro",
                detail="Macro stream detected. Install 'oletools' to extract and "
                       "score the macro source.")
        else:
            yield Finding(analyzer=self.name, title="No macro stream detected",
                          severity=Severity.INFO, category="macro")
