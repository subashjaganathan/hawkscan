"""macOS Mach-O analysis (compact stdlib header parser)."""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# Keyed by the magic read big-endian from the first 4 bytes. FE ED FA C* on disk
# is a big-endian (">") image; the byte-swapped CE/CF FA ED FE form is little
# (the on-disk bytes of a little-endian Mach-O), so it parses as "<".
_MAGICS = {
    0xfeedface: ("32-bit", ">"),
    0xfeedfacf: ("64-bit", ">"),
    0xcefaedfe: ("32-bit", "<"),
    0xcffaedfe: ("64-bit", "<"),
}
_FAT = {0xcafebabe, 0xbebafeca}
_FILETYPE = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 9: "dSYM"}

# Load-command identifiers (low bits; LC_REQ_DYLD 0x80000000 masked off).
_LC_SEGMENT, _LC_SEGMENT_64 = 0x1, 0x19
_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB = 0xC, 0x18
_LC_CODE_SIGNATURE = 0x1D
_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
_LC_RPATH = 0x1C
_DYLIB_LCS = {_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, 0x1F, 0x20, 0x23}
# VM protection bits.
_VM_WRITE, _VM_EXEC = 0x2, 0x4
# A dylib loaded from one of these locations is suspicious (real frameworks live
# under /System, /usr/lib, or inside the app bundle via @rpath/@loader_path).
_SUSPECT_DYLIB_PREFIXES = ("/tmp/", "/var/tmp/", "/Users/Shared/", "/private/tmp/")


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

        # Structural load-command analysis (signature, encryption, RWX, dylibs).
        yield from self._load_commands(data, endian, bits == "64-bit")

        # Quarantine / behaviour heuristics via strings.
        strings = ctx.cache.get("strings") or []
        blob = "\n".join(strings)
        for tok, (title, sev, cat) in {
            "com.apple.quarantine": ("Quarantine-attribute reference", Severity.LOW, "evasion"),
            "LaunchAgents": ("LaunchAgent persistence reference", Severity.MEDIUM, "persistence"),
            "LaunchDaemons": ("LaunchDaemon persistence reference", Severity.MEDIUM, "persistence"),
            "osascript": ("AppleScript execution reference", Severity.LOW, "execution"),
        }.items():
            if tok in blob:
                yield Finding(analyzer=self.name, title=title, severity=sev,
                              category=cat, detail=f"Contains {tok!r}.")

        yield from self._deep_indicators(blob)

    def _load_commands(self, data: bytes, endian: str, is64: bool) -> Iterable[Finding]:
        """Walk the Mach-O load commands for signature, encryption, segment
        protections and linked dylibs."""
        try:
            ncmds = struct.unpack_from(endian + "I", data, 16)[0]
        except struct.error:
            return
        if not 0 < ncmds < 10000:
            return
        off = 32 if is64 else 28
        signed = encrypted = rwx = False
        dylibs: list[str] = []
        suspect: list[str] = []
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            try:
                cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
            except struct.error:
                break
            if cmdsize < 8 or off + cmdsize > len(data):
                break
            low = cmd & 0x7fffffff
            if low == _LC_CODE_SIGNATURE:
                signed = True
            elif low in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
                # cryptid is the 3rd u32 after cmd/cmdsize/cryptoff/cryptsize.
                try:
                    cryptid = struct.unpack_from(endian + "I", data, off + 16)[0]
                    if cryptid != 0:
                        encrypted = True
                except struct.error:
                    pass
            elif low in (_LC_SEGMENT, _LC_SEGMENT_64):
                # maxprot/initprot sit after cmd,cmdsize,segname(16),vmaddr,vmsize,
                # fileoff,filesize. 64-bit uses Q for the four addr/size fields.
                try:
                    if is64:
                        maxprot, initprot = struct.unpack_from(
                            endian + "ii", data, off + 8 + 16 + 32)
                    else:
                        maxprot, initprot = struct.unpack_from(
                            endian + "ii", data, off + 8 + 16 + 16)
                    if (initprot & _VM_WRITE) and (initprot & _VM_EXEC):
                        rwx = True
                except struct.error:
                    pass
            elif low in _DYLIB_LCS:
                try:
                    name_off = struct.unpack_from(endian + "I", data, off + 8)[0]
                    raw = data[off + name_off:off + cmdsize].split(b"\x00")[0]
                    name = raw.decode("latin1", "ignore")
                    if name:
                        dylibs.append(name)
                        if name.startswith(_SUSPECT_DYLIB_PREFIXES):
                            suspect.append(name)
                except struct.error:
                    pass
            off += cmdsize

        if not signed:
            yield Finding(
                analyzer=self.name, title="Unsigned Mach-O (no LC_CODE_SIGNATURE)",
                severity=Severity.LOW, category="signature",
                detail="No code-signature load command; Gatekeeper blocks unsigned "
                       "binaries by default.")
        if encrypted:
            yield Finding(
                analyzer=self.name, title="Encrypted Mach-O segment (cryptid set)",
                severity=Severity.MEDIUM, category="packer",
                detail="LC_ENCRYPTION_INFO has a non-zero cryptid; the binary is "
                       "encrypted/protected (App Store DRM or anti-analysis packing).")
        if rwx:
            yield Finding(
                analyzer=self.name, title="Writable+executable (RWX) segment",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="A segment maps as both writable and executable; enables "
                       "self-modifying code / runtime-decoded payloads.")
        if suspect:
            yield Finding(
                analyzer=self.name,
                title=f"Dylib loaded from suspicious path: {suspect[0]}",
                severity=Severity.HIGH, category="injection",
                detail="A linked library loads from a world-writable/temp location; "
                       "typical of dylib hijacking or staged payloads.",
                data={"dylibs": suspect})

    def _deep_indicators(self, blob: str) -> Iterable[Finding]:
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
