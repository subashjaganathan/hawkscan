"""Linux/Unix ELF analysis using a compact stdlib header parser.

Parses the ELF header plus the program- and section-header tables to surface
structural malware traits - RWX (self-modifying) segments, an executable stack,
absent section headers (a UPX/packer hallmark), static linking, symbol
stripping and an unusual dynamic-linker path - then layers on a few high-signal
string heuristics. Capability scoring otherwise leans on the StringsAnalyzer
(ELF symbol/API names appear as strings).
"""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_ET = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
_MACHINE = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64",
            0x08: "MIPS", 0xf3: "RISC-V"}

# Program-header types and flags.
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP, _PT_GNU_STACK = 1, 2, 3, 0x6474e551
_PF_X, _PF_W = 0x1, 0x2
# Section-header types.
_SHT_SYMTAB = 2

# Legitimate dynamic-linker paths across distros/libc/arches.
_STD_INTERP = {
    "/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux.so.2",
    "/lib/ld-linux-aarch64.so.1", "/lib/ld-linux-armhf.so.3",
    "/system/bin/linker", "/system/bin/linker64",
    "/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1",
    "/lib/ld-musl-armhf.so.1", "/libexec/ld-elf.so.1",
    "/usr/lib/ld.so.1", "/lib/ld64.so.1", "/lib/ld64.so.2",
}


class ELFAnalyzer(Analyzer):
    name = "elf"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "elf"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 20 or data[:4] != b"\x7fELF":
            return
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        try:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        except struct.error:
            return

        yield Finding(
            analyzer=self.name,
            title=f"ELF {_ET.get(e_type, '?')}, "
                  f"{_MACHINE.get(e_machine, f'machine 0x{e_machine:x}')}, "
                  f"{'64' if is64 else '32'}-bit",
            severity=Severity.INFO, category="format")

        yield from self._structural(data, is64, endian, e_type)
        yield from self._string_heuristics(ctx)

    # ---- ELF structure --------------------------------------------------
    def _structural(self, data, is64, endian, e_type) -> Iterable[Finding]:
        try:
            if is64:
                e_phoff, e_shoff = struct.unpack_from(endian + "QQ", data, 32)
                (e_phentsize, e_phnum, e_shentsize, e_shnum) = \
                    struct.unpack_from(endian + "HHHH", data, 54)
            else:
                e_phoff, e_shoff = struct.unpack_from(endian + "II", data, 28)
                (e_phentsize, e_phnum, e_shentsize, e_shnum) = \
                    struct.unpack_from(endian + "HHHH", data, 42)
        except struct.error:
            return

        # --- program headers ---
        has_interp = has_dynamic = False
        interp_path = ""
        rwx = exec_stack = False
        for i in range(min(e_phnum, 128)):
            off = e_phoff + i * e_phentsize
            try:
                if is64:
                    p_type, p_flags = struct.unpack_from(endian + "II", data, off)
                    p_offset = struct.unpack_from(endian + "Q", data, off + 8)[0]
                    p_filesz = struct.unpack_from(endian + "Q", data, off + 32)[0]
                else:
                    p_type = struct.unpack_from(endian + "I", data, off)[0]
                    p_offset = struct.unpack_from(endian + "I", data, off + 4)[0]
                    p_filesz = struct.unpack_from(endian + "I", data, off + 16)[0]
                    p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
            except struct.error:
                break
            if p_type == _PT_INTERP:
                has_interp = True
                interp_path = data[p_offset:p_offset + min(p_filesz, 128)] \
                    .split(b"\x00")[0].decode("latin1", "ignore")
            elif p_type == _PT_DYNAMIC:
                has_dynamic = True
            elif p_type == _PT_LOAD and (p_flags & _PF_X) and (p_flags & _PF_W):
                rwx = True
            elif p_type == _PT_GNU_STACK and (p_flags & _PF_X):
                exec_stack = True

        if rwx:
            yield Finding(
                analyzer=self.name, title="Writable+executable (RWX) LOAD segment",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="A segment is both writable and executable; enables "
                       "self-modifying code / runtime-decoded payloads (packers, "
                       "shellcode loaders).")
        if exec_stack:
            yield Finding(
                analyzer=self.name, title="Executable stack (NX disabled)",
                severity=Severity.LOW, category="anti-analysis",
                detail="PT_GNU_STACK is executable; permits stack-resident "
                       "shellcode execution.")
        if interp_path and interp_path not in _STD_INTERP and \
                not any(k in interp_path for k in ("ld-", "ld.so", "linker", "ld64")):
            yield Finding(
                analyzer=self.name, title=f"Unusual ELF interpreter: {interp_path}",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="The program interpreter is not a standard dynamic linker; "
                       "may indicate a custom loader or tampering.")
        # Statically linked executable (no interpreter and no dynamic segment):
        # common for self-contained droppers/implants (also for Go binaries).
        if e_type == 2 and not has_interp and not has_dynamic:
            yield Finding(
                analyzer=self.name, title="Statically linked executable",
                severity=Severity.LOW, category="format",
                detail="No dynamic linker/segment; a self-contained binary that "
                       "carries all dependencies (common in portable malware).")

        # --- section headers ---
        if e_shnum == 0 or e_shoff == 0:
            yield Finding(
                analyzer=self.name, title="Section headers absent",
                severity=Severity.MEDIUM, category="packer",
                detail="The section-header table was removed; a hallmark of UPX "
                       "and other packers, and breaks many static tools.")
            return
        has_symtab = False
        for i in range(min(e_shnum, 256)):
            off = e_shoff + i * e_shentsize
            try:
                sh_type = struct.unpack_from(endian + "I", data, off + 4)[0]
            except struct.error:
                break
            if sh_type == _SHT_SYMTAB:
                has_symtab = True
                break
        if not has_symtab:
            yield Finding(
                analyzer=self.name, title="Stripped binary (no symbol table)",
                severity=Severity.LOW, category="anti-analysis",
                detail="No .symtab section; symbols were stripped to hinder "
                       "reverse engineering (also common in release builds).")

    # ---- string heuristics ---------------------------------------------
    def _string_heuristics(self, ctx: AnalysisContext) -> Iterable[Finding]:
        strings = ctx.cache.get("strings")
        if strings is None:
            return
        blob = "\n".join(strings)
        if "UPX!" in blob:
            yield Finding(
                analyzer=self.name, title="UPX packer artifact",
                severity=Severity.MEDIUM, category="packer",
                detail="Contains the UPX! marker; the binary is UPX-packed.")
        if "/proc/" in blob and "ptrace" in blob.lower():
            yield Finding(
                analyzer=self.name, title="Anti-debugging via ptrace",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="References ptrace and /proc; common self-debugging "
                       "evasion in Linux malware.")
        for tok, (title, sev, cat) in {
            "LD_PRELOAD": ("LD_PRELOAD reference (userland rootkit)", Severity.MEDIUM, "persistence"),
            "/etc/cron": ("Cron persistence reference", Severity.MEDIUM, "persistence"),
            "/etc/rc.local": ("rc.local persistence reference", Severity.MEDIUM, "persistence"),
            "/etc/systemd/system": ("systemd service persistence reference", Severity.MEDIUM, "persistence"),
            "/.ssh/authorized_keys": ("SSH authorized_keys access", Severity.MEDIUM, "credential-access"),
            "iptables": ("Firewall manipulation reference", Severity.LOW, "evasion"),
        }.items():
            if tok in blob:
                yield Finding(analyzer=self.name, title=title, severity=sev,
                              category=cat, detail=f"Contains {tok!r}.")
