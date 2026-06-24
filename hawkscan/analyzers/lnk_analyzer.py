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

# LinkFlags bits.
_HAS_IDLIST = 0x00000001
_HAS_LINKINFO = 0x00000002
_HAS_NAME = 0x00000004
_HAS_RELPATH = 0x00000008
_HAS_WORKINGDIR = 0x00000010
_HAS_ARGUMENTS = 0x00000020
_HAS_ICON = 0x00000040
_IS_UNICODE = 0x00000080

_SUSPECT = ("powershell", "cmd.exe", "cmd /c", "/c ", "mshta", "wscript",
            "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin",
            "-enc", "-w hidden", "-nop", "iex", "downloadstring", "http://",
            "https://", "frombase64string", "curl", "%comspec%", "-e ")
# Icon references that imply a document/media file while the target runs a shell.
_DOC_ICONS = ("acrord", "winword", "excel", "powerpnt", "wordpad", "notepad",
              ".pdf", ".doc", ".xls", ".ppt", ".txt", ".jpg", ".png")


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

        # Structured parse: recover the exact COMMAND_LINE_ARGUMENTS, target and
        # icon from StringData (precise, vs guessing from loose strings).
        strings, str_end = self._parse_stringdata(data, link_flags)
        args = strings.get("args", "")
        icon = strings.get("icon", "")
        relpath = strings.get("relpath", "")

        # Behavioural command line: prefer the parsed args; fall back to a loose
        # string sweep if structured parsing recovered nothing.
        cmd_blob = (args + " " + relpath).lower()
        if not cmd_blob.strip():
            ascii_s, _ = extract_strings(data, min_len=4)
            cmd_blob = "\n".join(ascii_s).lower()
        hits = sorted({t for t in _SUSPECT if t in cmd_blob})

        if hits:
            sev = (Severity.HIGH if any(h in hits for h in
                   ("powershell", "mshta", "iex", "downloadstring", "-enc",
                    "frombase64string")) else Severity.MEDIUM)
            detail = "Embedded command indicators: " + ", ".join(hits[:8])
            if args:
                detail += f" | args: {args[:200]}"
            yield Finding(
                analyzer=self.name,
                title="Shortcut launches a command interpreter / download",
                severity=sev, category="execution", detail=detail,
                data={"lnk_args": args[:1000]} if args else None)

            # Icon spoofing: a document/media icon over a shell-launching target.
            if icon and any(d in icon.lower() for d in _DOC_ICONS):
                yield Finding(
                    analyzer=self.name, title="Icon spoofing (document icon, shell target)",
                    severity=Severity.HIGH, category="masquerading",
                    detail=f"Shortcut shows a document/media icon ({icon[:80]}) but "
                           "launches a command interpreter.")
        elif has_args:
            yield Finding(
                analyzer=self.name,
                title="Shortcut carries command-line arguments",
                severity=Severity.LOW, category="execution",
                detail=(f"Args: {args[:200]}" if args else
                        "LNK targets are usually plain paths; arguments warrant a look."))

        # Data well beyond the parsed structures = an appended/embedded payload.
        if str_end and len(data) - str_end > 4096:
            yield Finding(
                analyzer=self.name,
                title=f"Embedded data after LNK structures ({len(data) - str_end:,} bytes)",
                severity=Severity.MEDIUM, category="dropper",
                detail="Large trailing data beyond the shortcut structures; LNK "
                       "malware often appends a script/PE payload here.")

    def _parse_stringdata(self, data: bytes, flags: int):
        """Walk past the optional ID list and LinkInfo, then read the
        length-prefixed StringData fields. Returns (dict, offset-after-strings)."""
        off = 76
        n = len(data)
        try:
            if flags & _HAS_IDLIST:
                if off + 2 > n:
                    return {}, 0
                off += 2 + struct.unpack_from("<H", data, off)[0]
            if flags & _HAS_LINKINFO:
                if off + 4 > n:
                    return {}, 0
                li = struct.unpack_from("<I", data, off)[0]
                if li < 4:
                    return {}, 0
                off += li
            unicode = bool(flags & _IS_UNICODE)
            out: dict[str, str] = {}
            for key, bit in (("name", _HAS_NAME), ("relpath", _HAS_RELPATH),
                             ("workdir", _HAS_WORKINGDIR), ("args", _HAS_ARGUMENTS),
                             ("icon", _HAS_ICON)):
                if not (flags & bit):
                    continue
                if off + 2 > n:
                    break
                cnt = struct.unpack_from("<H", data, off)[0]
                off += 2
                nbytes = cnt * 2 if unicode else cnt
                raw = data[off:off + nbytes]
                off += nbytes
                out[key] = raw.decode("utf-16le" if unicode else "latin1", "ignore")
        except (struct.error, IndexError):
            return {}, 0
        return out, off
