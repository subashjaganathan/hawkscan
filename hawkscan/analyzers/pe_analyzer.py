"""Windows PE (EXE/DLL/SYS) analysis.

Uses `pefile` when installed for import-table, section-entropy and signature
checks. Falls back to a minimal stdlib header parse so it still reports
something useful without the dependency.
"""

from __future__ import annotations

import re
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
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])

        # imphash (import-table fingerprint) + rich header hash: both are
        # stable identifiers useful for clustering samples into families.
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = ""
        if imphash:
            yield Finding(analyzer=self.name, title=f"imphash: {imphash}",
                          severity=Severity.INFO, category="identity",
                          data={"imphash": imphash})
        try:
            rich = pe.parse_rich_header()
        except Exception:
            rich = None
        if rich and rich.get("checksum") is not None:
            yield Finding(analyzer=self.name,
                          title=f"Rich header present (xor key 0x{rich['checksum']:x})",
                          severity=Severity.INFO, category="identity",
                          detail="Compiler/toolchain fingerprint.")

        # TLS callbacks run before the entry point - a common early-execution /
        # anti-analysis technique.
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls and getattr(tls.struct, "AddressOfCallBacks", 0):
            # Informational: TLS callbacks are common in legitimate CRT binaries
            # for thread-local init, so this should not drive the verdict alone.
            yield Finding(
                analyzer=self.name, title="TLS callback(s) present",
                severity=Severity.INFO, category="anti-analysis",
                detail="Code referenced via TLS callbacks executes before main(); "
                       "can be used for early execution / anti-debugging.")

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
        wx_sections = []
        for section in pe.sections:
            raw_name = section.Name.rstrip(b"\x00")
            if raw_name in _KNOWN_PACKER_SECTIONS:
                packer_hit = True
            # Writable + executable section = self-modifying / unpacking stub.
            ch = section.Characteristics
            if (ch & 0x20000000) and (ch & 0x80000000):  # EXECUTE + WRITE
                wx_sections.append(raw_name.decode("latin1", "ignore") or "(unnamed)")
            # A section far larger in memory than on disk is a classic packer
            # decompression stub.
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0x1000:
                yield Finding(
                    analyzer=self.name,
                    title=f"Section {raw_name.decode('latin1')!r} has no raw data "
                          "but large virtual size",
                    severity=Severity.LOW, category="packer",
                    detail="Memory-only section; typical of a packer unpacking stub.")
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
        if wx_sections:
            yield Finding(
                analyzer=self.name,
                title=f"Writable+executable section(s): {', '.join(wx_sections)}",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="W+X (RWX) sections allow self-modifying code; common in "
                       "packed or shellcode-bearing binaries.")
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

        # Export table analysis (DLLs). Tell-tale exports reveal malicious DLLs.
        yield from self._analyze_exports(pe)

        # Authenticode presence (not validity — that needs OS APIs).
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        from ..intel import sigcheck
        status, detail = sigcheck.verify(ctx.info.path)
        if status == "valid":
            yield Finding(analyzer=self.name, title="Digitally signed (valid)",
                          severity=Severity.INFO, category="signature", detail=detail)
        elif status == "invalid":
            yield Finding(analyzer=self.name, title="Invalid digital signature",
                          severity=Severity.HIGH, category="signature", detail=detail)
        elif status == "unsigned" or (status == "unknown" and
                                      (sec_dir.VirtualAddress == 0 or sec_dir.Size == 0)):
            # Off-Windows we can't verify; fall back to embedded-presence only.
            note = ("No embedded Authenticode signature." if status == "unknown"
                    else detail)
            yield Finding(analyzer=self.name, title="Not digitally signed",
                          severity=Severity.LOW, category="signature", detail=note)
        elif status == "unknown" and sec_dir.Size > 0:
            yield Finding(analyzer=self.name, title="Signature present (unverified)",
                          severity=Severity.INFO, category="signature",
                          detail="Embedded signature present; validity not checked "
                                 "on this platform.")

        # Best-effort signer details from the embedded certificate blob. The
        # PKCS#7 stores X.509 names as readable strings (CN=, O=); pulling them
        # avoids a full ASN.1 parser while still surfacing who signed it.
        if sec_dir.VirtualAddress and sec_dir.Size:
            try:
                blob = ctx.read_all()[sec_dir.VirtualAddress:
                                      sec_dir.VirtualAddress + sec_dir.Size]
                names = re.findall(rb"(?:CN|O|OU)=([\x20-\x7e]{3,64})", blob)
                seen, uniq = set(), []
                for n in names:
                    s = n.decode("latin1", "ignore").strip()
                    if s and s not in seen:
                        seen.add(s); uniq.append(s)
                if uniq:
                    yield Finding(analyzer=self.name, title="Certificate signer",
                                  severity=Severity.INFO, category="signature",
                                  detail="; ".join(uniq[:4]),
                                  data={"cert_names": uniq[:10]})
            except Exception:
                pass

        # Overlay: data appended after the last section. Large, high-entropy
        # overlays often carry a bundled/encrypted second-stage payload.
        try:
            ov_off = pe.get_overlay_data_start_offset()
        except Exception:
            ov_off = None
        if ov_off is not None:
            data_all = ctx.read_all()
            # Exclude the Authenticode certificate table: it lives after the last
            # section (so pefile counts it as overlay) and is high-entropy, which
            # would otherwise flag every signed binary. SECURITY dir VirtualAddress
            # is a raw file offset.
            cert_lo = sec_dir.VirtualAddress
            cert_hi = cert_lo + sec_dir.Size if cert_lo else 0
            if cert_hi and cert_lo >= ov_off:
                overlay = data_all[ov_off:cert_lo] + data_all[cert_hi:]
            else:
                overlay = data_all[ov_off:]
            if len(overlay) > 2048:
                ent = shannon_entropy(overlay)
                high = ent >= 7.2
                yield Finding(
                    analyzer=self.name,
                    title=f"Overlay data appended ({len(overlay):,} bytes, "
                          f"entropy {ent:.2f})",
                    severity=Severity.MEDIUM if high else Severity.LOW,
                    category="dropper",
                    detail="Data after the last section (excluding any signature); "
                           "high entropy suggests a bundled or encrypted payload."
                           if high else "Data appended after the last PE section.",
                    data={"overlay_size": len(overlay), "entropy": round(ent, 3)},
                )

        # Version-info resource strings (CompanyName, OriginalFilename, ...).
        version = self._version_info(pe)
        if version:
            shown = ", ".join(f"{k}={v}" for k, v in list(version.items())[:5])
            yield Finding(analyzer=self.name, title="Version info present",
                          severity=Severity.INFO, category="metadata",
                          detail=shown, data={"version_info": version})
            # OriginalFilename disagreeing with the on-disk name can indicate a
            # renamed tool. Renaming is common/benign, so this is LOW and skips
            # generic placeholder values to avoid false positives.
            orig = version.get("OriginalFilename", "").strip().lower()
            actual = ctx.info.path.name.lower()
            placeholders = {"", "unknown_file", "unknown", "originalfilename",
                            "filename", "none"}
            if (orig and orig not in placeholders and actual
                    and not actual.startswith(orig.rsplit(".", 1)[0])
                    and orig.rsplit(".", 1)[0] not in actual):
                yield Finding(
                    analyzer=self.name,
                    title=f"OriginalFilename differs ('{orig}' vs '{actual}')",
                    severity=Severity.LOW, category="masquerading",
                    detail="The embedded OriginalFilename differs from the file on "
                           "disk; the binary may have been renamed.",
                )

        # Resource directory: count entries and look for embedded executables.
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            rtypes, entries, embedded = 0, 0, False
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rtypes += 1
                for rid in getattr(getattr(rtype, "directory", None), "entries", []):
                    for lang in getattr(getattr(rid, "directory", None), "entries", []):
                        entries += 1
                        try:
                            blob = pe.get_data(lang.data.struct.OffsetToData, 4)
                        except Exception:
                            continue
                        if blob[:2] == b"MZ" or blob[:4] == b"\x7fELF":
                            embedded = True
            yield Finding(analyzer=self.name,
                          title=f"{entries} resource(s) in {rtypes} type(s)",
                          severity=Severity.INFO, category="metadata")
            if embedded:
                yield Finding(
                    analyzer=self.name,
                    title="Embedded executable in resource section",
                    severity=Severity.HIGH, category="dropper",
                    detail="A resource entry begins with an executable header; "
                           "the binary carries an embedded payload.",
                )

    # Generic export names that, when they dominate a small export table, are
    # typical of beacon/loader DLLs rather than legitimate libraries.
    _GENERIC_EXPORTS = {"start", "run", "main", "init", "voidfunc", "go", "x",
                        "load", "begin", "exec", "doit"}

    def _analyze_exports(self, pe) -> Iterable[Finding]:
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if not exp or not getattr(exp, "symbols", None):
            return
        names, forwarders = [], 0
        for sym in exp.symbols:
            if sym.name:
                names.append(sym.name.decode("latin1", "ignore"))
            if getattr(sym, "forwarder", None):
                forwarders += 1

        yield Finding(analyzer=self.name,
                      title=f"DLL with {len(names)} named export(s)",
                      severity=Severity.INFO, category="exports",
                      data={"exports": names[:50]})

        lower = {n.lower() for n in names}

        # Reflective loader export = reflective DLL injection (e.g. Cobalt Strike).
        if any("reflectiveloader" in n for n in lower):
            yield Finding(
                analyzer=self.name, title="Reflective loader export",
                severity=Severity.HIGH, category="injection",
                detail="Exports a ReflectiveLoader; used for reflective DLL "
                       "injection. ATT&CK: T1620 Reflective Code Loading.")

        # regsvr32-loadable entry points (also legitimate COM, so informational).
        com = lower & {"dllregisterserver", "dllinstall", "dllunregisterserver"}
        if com:
            yield Finding(
                analyzer=self.name,
                title=f"COM/regsvr32 entry point(s): {', '.join(sorted(com))}",
                severity=Severity.INFO, category="exports",
                detail="DLL can be loaded via regsvr32; common LOLBin execution path.")

        # A small export table made up of generic names is a loader/beacon trait.
        if names and len(names) <= 4 and lower and lower <= self._GENERIC_EXPORTS:
            yield Finding(
                analyzer=self.name,
                title=f"DLL exports only generic names ({', '.join(sorted(lower))})",
                severity=Severity.MEDIUM, category="exports",
                detail="A tiny export table of generic names is typical of "
                       "injected loader/beacon DLLs rather than real libraries.")

        if forwarders and forwarders == len(exp.symbols):
            yield Finding(
                analyzer=self.name, title="All exports are forwarders",
                severity=Severity.MEDIUM, category="exports",
                detail="Fully-forwarding DLL; can indicate DLL proxying/hijacking.")

    @staticmethod
    def _version_info(pe) -> dict:
        out: dict[str, str] = {}
        for fi_list in getattr(pe, "FileInfo", []) or []:
            for entry in fi_list:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in getattr(st, "entries", {}).items():
                        try:
                            out[k.decode("latin1", "ignore")] = v.decode("latin1", "ignore")
                        except Exception:
                            continue
        return out

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
