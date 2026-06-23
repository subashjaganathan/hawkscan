"""macOS Mach-O analysis (compact stdlib header parser)."""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_MAGICS = {
    0xfeedface: ("32-bit", "<"),
    0xfeedfacf: ("64-bit", "<"),
    0xcefaedfe: ("32-bit", ">"),
    0xcffaedfe: ("64-bit", ">"),
}
_FAT = {0xcafebabe, 0xbebafeca}
_FILETYPE = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 9: "dSYM"}


class MachOAnalyzer(Analyzer):
    name = "macho"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "macho"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 8:
            return
        magic = struct.unpack_from(">I", data, 0)[0]

        if magic in _FAT:
            n = struct.unpack_from(">I", data, 4)[0]
            yield Finding(
                analyzer=self.name,
                title=f"Mach-O universal (fat) binary, {n} architecture slice(s)",
                severity=Severity.INFO,
                category="format",
            )
            return

        if magic not in _MAGICS:
            return
        bits, endian = _MAGICS[magic]
        try:
            filetype = struct.unpack_from(endian + "I", data, 12)[0]
        except struct.error:
            filetype = 0
        yield Finding(
            analyzer=self.name,
            title=f"Mach-O {_FILETYPE.get(filetype, 'binary')}, {bits}",
            severity=Severity.INFO,
            category="format",
        )

        # Code-signing / quarantine heuristics via strings.
        strings = ctx.cache.get("strings") or []
        blob = "\n".join(strings)
        if "LC_CODE_SIGNATURE" not in blob and "CodeDirectory" not in blob:
            yield Finding(
                analyzer=self.name,
                title="No obvious code-signature blob",
                severity=Severity.LOW,
                category="signature",
                detail="Unsigned Mach-O binaries are blocked by Gatekeeper by default.",
            )
        for tok, (title, sev, cat) in {
            "com.apple.quarantine": ("Quarantine-attribute reference", Severity.LOW, "evasion"),
            "LaunchAgents": ("LaunchAgent persistence reference", Severity.MEDIUM, "persistence"),
            "LaunchDaemons": ("LaunchDaemon persistence reference", Severity.MEDIUM, "persistence"),
            "osascript": ("AppleScript execution reference", Severity.LOW, "execution"),
        }.items():
            if tok in blob:
                yield Finding(analyzer=self.name, title=title, severity=sev,
                              category=cat, detail=f"Contains {tok!r}.")

        # Deeper macOS behaviour indicators (privilege escalation, credential
        # and TCC/keychain access, evasion) seen as strings.
        for tok, (title, sev, cat) in {
            "AuthorizationExecuteWithPrivileges":
                ("Privilege escalation API (deprecated AEWP)", Severity.HIGH, "privilege"),
            "STPrivilegedTask":
                ("Privileged-task helper (privilege escalation)", Severity.MEDIUM, "privilege"),
            "authorized_keys":
                ("SSH authorized_keys access", Severity.HIGH, "credential-access"),
            "id_rsa":
                ("SSH private key reference", Severity.MEDIUM, "credential-access"),
            "login.keychain":
                ("Keychain access", Severity.MEDIUM, "credential-access"),
            "security find-generic-password":
                ("Keychain credential dump (security CLI)", Severity.HIGH, "credential-access"),
            "spctl --master-disable":
                ("Gatekeeper disable", Severity.HIGH, "evasion"),
            "csrutil disable":
                ("SIP disable attempt", Severity.HIGH, "evasion"),
            "TCC.db":
                ("TCC privacy database access", Severity.HIGH, "privacy"),
            "DYLD_INSERT_LIBRARIES":
                ("Dylib injection via DYLD_INSERT_LIBRARIES", Severity.MEDIUM, "injection"),
        }.items():
            if tok in blob:
                yield Finding(analyzer=self.name, title=title, severity=sev,
                              category=cat, detail=f"Contains {tok!r}.")
