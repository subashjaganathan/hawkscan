"""Windows PE (EXE/DLL/SYS) analysis.

Uses `pefile` when installed for import-table, section-entropy and signature
checks. Falls back to a minimal stdlib header parse so it still reports
something useful without the dependency.
"""

from __future__ import annotations

import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from .entropy import shannon_entropy
from ..core.findings import Finding, Severity

try:
    import pefile  # type: ignore
    _HAVE_PEFILE = True
except Exception:
    _HAVE_PEFILE = False

_KNOWN_PACKER_SECTIONS = {
    b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b"ASPack",
    b".nsp0", b".nsp1", b"FSG!", b".petite", b".themida", b"pebundle",
}


class PEAnalyzer(Analyzer):
    name = "pe"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "pe"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        if _HAVE_PEFILE:
            yield from self._analyze_pefile(ctx)
        else:
            yield from self._analyze_basic(ctx)

    # ---- rich path -------------------------------------------------------
    def _analyze_pefile(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            pe = pefile.PE(data=ctx.read_all(), fast_load=True)
        except pefile.PEFormatError as exc:
            yield Finding(
                analyzer=self.name,
                title="Malformed PE header",
                severity=Severity.MEDIUM,
                category="format",
                detail=f"pefile could not parse the binary ({exc}); it may be "
                       "truncated, corrupt, or deliberately malformed to thwart tools.",
            )
            return
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])

        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        yield Finding(
            analyzer=self.name,
            title=f"PE {'DLL' if is_dll else 'executable'}, "
                  f"{'64-bit' if pe.OPTIONAL_HEADER.Magic == 0x20b else '32-bit'}",
            severity=Severity.INFO,
            category="format",
            data={"timestamp": pe.FILE_HEADER.TimeDateStamp},
        )

        # Section names + per-section entropy.
        packer_hit = False
        for section in pe.sections:
            raw_name = section.Name.rstrip(b"\x00")
            if raw_name in _KNOWN_PACKER_SECTIONS:
                packer_hit = True
            sdata = section.get_data()
            if sdata:
                ent = shannon_entropy(sdata)
                if ent >= 7.5 and len(sdata) > 1024:
                    yield Finding(
                        analyzer=self.name,
                        title=f"High-entropy section {raw_name.decode('latin1')!r} "
                              f"({ent:.2f})",
                        severity=Severity.LOW,
                        category="packer",
                        detail="Packed/encrypted section content.",
                    )
        if packer_hit:
            yield Finding(
                analyzer=self.name,
                title="Known packer section name detected",
                severity=Severity.MEDIUM,
                category="packer",
                detail="Section names match a known packer (UPX/ASPack/Themida/etc.).",
            )

        # Collect the full import table for the CapabilityAnalyzer, which owns
        # API-to-capability/ATT&CK scoring (so we don't double-count here).
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            api_names: set[str] = set()
            api_addrs: dict[str, str] = {}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        n = imp.name.decode("latin1", "ignore")
                        api_names.add(n)
                        if imp.address:
                            api_addrs[n] = f"0x{imp.address:x}"
            ctx.cache["api_names"] = api_names
            ctx.cache["api_addrs"] = api_addrs
        else:
            yield Finding(
                analyzer=self.name,
                title="No import table",
                severity=Severity.MEDIUM,
                category="packer",
                detail="Missing/empty imports often indicate a packed binary that "
                       "resolves APIs dynamically at runtime.",
            )

        # Authenticode presence (not validity — that needs OS APIs).
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            yield Finding(
                analyzer=self.name,
                title="Not digitally signed",
                severity=Severity.LOW,
                category="signature",
                detail="No embedded Authenticode signature.",
            )

        # Overlay: data appended after the last section. Large, high-entropy
        # overlays often carry a bundled/encrypted second-stage payload.
        try:
            ov_off = pe.get_overlay_data_start_offset()
        except Exception:
            ov_off = None
        if ov_off is not None:
            overlay = ctx.read_all()[ov_off:]
            if len(overlay) > 2048:
                ent = shannon_entropy(overlay)
                high = ent >= 7.2
                yield Finding(
                    analyzer=self.name,
                    title=f"Overlay data appended ({len(overlay):,} bytes, "
                          f"entropy {ent:.2f})",
                    severity=Severity.MEDIUM if high else Severity.LOW,
                    category="dropper",
                    detail="Data after the last section; high entropy suggests a "
                           "bundled or encrypted payload." if high else
                           "Data appended after the last PE section.",
                    data={"overlay_size": len(overlay), "entropy": round(ent, 3)},
                )

        # Resource directory: an embedded PE inside a resource is a classic
        # dropper pattern (the loader carries its payload as a resource).
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for rid in getattr(rtype, "directory", {}).entries if hasattr(rtype, "directory") else []:
                    for lang in getattr(rid, "directory", {}).entries if hasattr(rid, "directory") else []:
                        try:
                            rva = lang.data.struct.OffsetToData
                            size = lang.data.struct.Size
                            blob = pe.get_data(rva, min(size, 4))
                        except Exception:
                            continue
                        if blob[:2] == b"MZ":
                            yield Finding(
                                analyzer=self.name,
                                title="Embedded PE in resource section",
                                severity=Severity.HIGH,
                                category="dropper",
                                detail="A resource entry begins with an MZ header; "
                                       "the binary carries an embedded executable.",
                            )
                            return  # one is enough

    # ---- fallback path ---------------------------------------------------
    def _analyze_basic(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
                raise ValueError("bad PE signature")
            machine, num_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
            chars = struct.unpack_from("<H", data, e_lfanew + 22)[0]
            is_dll = bool(chars & 0x2000)
            arch = {0x14c: "32-bit (x86)", 0x8664: "64-bit (x64)",
                    0xaa64: "ARM64"}.get(machine, f"machine 0x{machine:x}")
            yield Finding(
                analyzer=self.name,
                title=f"PE {'DLL' if is_dll else 'executable'}, {arch}, "
                      f"{num_sections} sections",
                severity=Severity.INFO,
                category="format",
            )
        except Exception:
            yield Finding(
                analyzer=self.name,
                title="Malformed PE header",
                severity=Severity.MEDIUM,
                category="format",
                detail="Could not parse the PE header; the file may be corrupt or "
                       "deliberately malformed to thwart tools.",
            )
        yield Finding(
            analyzer=self.name,
            title="Install 'pefile' for deep PE analysis",
            severity=Severity.INFO,
            category="format",
            detail="Import-table, section-entropy and signature checks are skipped "
                   "without the optional 'pefile' package.",
        )
