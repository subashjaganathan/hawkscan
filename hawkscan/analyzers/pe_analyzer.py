"""Windows PE (EXE/DLL/SYS) analysis.

Uses `pefile` when installed for import-table, section-entropy and signature
checks. Falls back to a minimal stdlib header parse so it still reports
something useful without the dependency.
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
from datetime import datetime, timezone
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

# Section names produced by mainstream toolchains (MSVC, MinGW, Go, Rust, etc.).
# Anything outside this set (and not a known packer) is worth noting.
_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
    ".reloc", ".tls", ".pdata", ".xdata", ".debug", ".didat", ".gfids",
    ".00cfg", ".voltbl", ".sxdata", ".rodata", ".init", ".fini",
    "code", "data", ".code", ".crt", ".gnu_deb", ".symtab", ".strtab",
    ".note", ".comment", ".eh_fram", ".CRT", ".INIT",
    # Recent MSVC / Windows hotpatch & CFG sections (present on clean binaries).
    "fothk", ".fothk", "_RDATA", ".gxfg", ".retplne", ".giats", ".gehcont",
    ".gfids", ".wixburn", ".detourc", ".detourd",
}
# APIs whose presence as nearly the *only* imports indicates the binary resolves
# the rest of its API surface at runtime (a packer / API-hiding trait).
_RESOLVER_APIS = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                  "LoadLibraryExW", "GetProcAddress", "GetModuleHandleA",
                  "GetModuleHandleW"}

# Magic prefixes of media/compressed formats that are *legitimately* high
# entropy, so a high-entropy resource with one of these is not a payload signal.
_MEDIA_MAGICS = (
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"RIFF", b"OggS",
    b"ID3", b"\x1f\x8b", b"\x00\x00\x01\x00", b"\x00\x00\x02\x00",  # ICO/CUR
    b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x20ftyp", b"DDS ", b"\x49\x49\x2a\x00",
)


def _is_media(header: bytes) -> bool:
    return any(header.startswith(m) for m in _MEDIA_MAGICS)


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
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
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
            # Rich-header hash: MD5 of the xor-cleared @comp.id records. Like
            # imphash, it clusters samples built on the same dev toolchain.
            rich_hash = ""
            try:
                clear = rich.get("clear_data") or b""
                if clear:
                    rich_hash = hashlib.md5(clear).hexdigest()
            except Exception:
                rich_hash = ""
            yield Finding(
                analyzer=self.name,
                title=(f"Rich header present (richhash {rich_hash})" if rich_hash
                       else f"Rich header present (xor key 0x{rich['checksum']:x})"),
                severity=Severity.INFO, category="identity",
                detail="Compiler/toolchain fingerprint; richhash clusters sibling "
                       "samples from the same build environment.",
                data={"richhash": rich_hash} if rich_hash else None)

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

        # Reproducible-build binaries (notably modern Microsoft ones) store a
        # content hash in TimeDateStamp, flagged by a REPRO debug entry. Detect
        # it so the timestamp-sanity check does not false-positive on them.
        is_repro = any(getattr(d.struct, "Type", None) == 16
                       for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or [])
        yield from self._header_anomalies(pe, is_dll, is_repro)

        # Section names + per-section entropy.
        packer_hit = False
        wx_sections = []
        nonstd_sections: list[str] = []
        for section in pe.sections:
            raw_name = section.Name.rstrip(b"\x00")
            name_s = raw_name.decode("latin1", "ignore")
            if raw_name in _KNOWN_PACKER_SECTIONS:
                packer_hit = True
            elif name_s and name_s not in _STANDARD_SECTIONS:
                nonstd_sections.append(name_s or "(unnamed)")
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
        # Non-standard section names (not a recognised toolchain/packer name).
        # LOW on its own: legitimate binaries occasionally use custom sections.
        if nonstd_sections:
            yield Finding(
                analyzer=self.name,
                title=f"Non-standard section name(s): {', '.join(nonstd_sections[:6])}",
                severity=Severity.LOW, category="packer",
                detail="Section names outside the common toolchain set; seen in "
                       "packed, custom-linked, or hand-crafted binaries.",
                data={"sections": nonstd_sections[:16]})

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
            # A tiny import table consisting mostly of LoadLibrary/GetProcAddress
            # means the real API surface is resolved at runtime - an API-hiding /
            # unpacking trait rather than a normally-linked program.
            if 0 < len(api_names) <= 12 and (api_names & _RESOLVER_APIS) and \
                    len(api_names - _RESOLVER_APIS) <= 4:
                yield Finding(
                    analyzer=self.name,
                    title="Imports limited to dynamic API resolution",
                    severity=Severity.MEDIUM, category="packer",
                    detail="The import table is dominated by LoadLibrary/"
                           "GetProcAddress; the binary resolves its real APIs at "
                           "runtime to hide capability from static tools.")
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

        # Manifest execution level + debug PDB path.
        yield from self._manifest_and_debug(pe, ctx.read_all())

        # Resource directory: count entries, look for embedded executables, and
        # flag a large high-entropy resource (encrypted/compressed payload).
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            rtypes, entries, embedded = 0, 0, False
            best_ent, best_size = 0.0, 0
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rtypes += 1
                for rid in getattr(getattr(rtype, "directory", None), "entries", []):
                    for lang in getattr(getattr(rid, "directory", None), "entries", []):
                        entries += 1
                        try:
                            off = lang.data.struct.OffsetToData
                            size = lang.data.struct.Size
                            blob = pe.get_data(off, min(size, 16))
                        except Exception:
                            continue
                        if blob[:2] == b"MZ" or blob[:4] == b"\x7fELF":
                            embedded = True
                        # Skip naturally high-entropy media (icons/images/audio/
                        # video/compressed); only raw encrypted blobs are notable.
                        if size > 4096 and not _is_media(blob):
                            try:
                                full = pe.get_data(off, min(size, 1 << 20))
                                ent = shannon_entropy(full)
                                if ent > best_ent:
                                    best_ent, best_size = ent, size
                            except Exception:
                                pass
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
            elif best_ent >= 7.2 and best_size > 4096:
                yield Finding(
                    analyzer=self.name,
                    title=f"High-entropy resource ({best_size:,} bytes, "
                          f"entropy {best_ent:.2f})",
                    severity=Severity.LOW, category="dropper",
                    detail="A resource is high-entropy without a known header; "
                           "often an encrypted or compressed embedded payload.",
                    data={"resource_entropy": round(best_ent, 3),
                          "resource_size": best_size})

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

    def _header_anomalies(self, pe, is_dll: bool, is_repro: bool = False) -> Iterable[Finding]:
        """Entry-point placement, PE checksum and compile-timestamp sanity."""
        # --- entry point ---
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep == 0 and not is_dll:
            yield Finding(
                analyzer=self.name, title="Entry point is zero",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail="An executable with AddressOfEntryPoint=0 is abnormal; seen "
                       "in corrupted or manually-mapped/injected images.")
        elif ep:
            sec = None
            try:
                sec = pe.get_section_by_rva(ep)
            except Exception:
                sec = None
            if sec is None:
                yield Finding(
                    analyzer=self.name,
                    title="Entry point outside all sections",
                    severity=Severity.HIGH, category="anti-analysis",
                    detail="AddressOfEntryPoint does not map into any section; "
                           "typical of malformed or packed/injected binaries.")
            else:
                ch = sec.Characteristics
                ep_name = sec.Name.rstrip(b'\x00').decode('latin1', 'ignore')
                if ch & 0x80000000:  # writable
                    yield Finding(
                        analyzer=self.name,
                        title=f"Entry point in writable section {ep_name!r}",
                        severity=Severity.MEDIUM, category="packer",
                        detail="Execution starts in a writable section; the code "
                               "rewrites itself (self-modifying / unpacking stub).")
                if pe.sections and sec is pe.sections[-1] and len(pe.sections) > 1 \
                        and not (ch & 0x80000000):
                    yield Finding(
                        analyzer=self.name,
                        title=f"Entry point in last section {ep_name!r}",
                        severity=Severity.LOW, category="packer",
                        detail="Compilers place the entry point in an early code "
                               "section; an EP in the final section suggests a "
                               "packer stub.")

        # --- checksum ---
        stored = pe.OPTIONAL_HEADER.CheckSum
        try:
            computed = pe.generate_checksum()
        except Exception:
            computed = stored
        if stored and computed and stored != computed:
            yield Finding(
                analyzer=self.name,
                title="PE checksum invalid",
                severity=Severity.LOW, category="format",
                detail=f"Stored checksum 0x{stored:08x} != computed 0x{computed:08x}; "
                       "the file was patched/modified after linking (drivers and "
                       "signed binaries normally carry a correct checksum).")

        # --- timestamp ---
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            yield Finding(
                analyzer=self.name, title="Zeroed compile timestamp",
                severity=Severity.LOW, category="anti-analysis",
                detail="TimeDateStamp=0 hides build time (anti-forensics, or a "
                       "reproducible build).")
        elif not is_repro and (ts > int(time.time()) + 86400 or ts >= 0xF0000000):
            when = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") \
                if ts < 0xF0000000 else f"raw 0x{ts:08x}"
            yield Finding(
                analyzer=self.name, title="Future/forged compile timestamp",
                severity=Severity.MEDIUM, category="anti-analysis",
                detail=f"TimeDateStamp ({when}) is in the future; commonly forged "
                       "to defeat timeline analysis.")

    def _manifest_and_debug(self, pe, data: bytes) -> Iterable[Finding]:
        """requestedExecutionLevel from the embedded manifest, and the PDB path
        from the debug directory (an attribution IOC)."""
        # Debug directory -> CodeView PDB path.
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            pdb = getattr(getattr(dbg, "entry", None), "PdbFileName", None)
            if not pdb:
                continue
            path = pdb.rstrip(b"\x00").decode("latin1", "ignore")
            if not path:
                continue
            leaks_user = bool(re.search(r"[A-Za-z]:\\Users\\|/home/", path))
            yield Finding(
                analyzer=self.name, title="Debug PDB path present",
                severity=Severity.LOW if leaks_user else Severity.INFO,
                category="metadata",
                detail=(f"PDB path: {path}" + (" (leaks developer username/layout)"
                        if leaks_user else "")),
                data={"pdb_path": path})
            break

        # RT_MANIFEST (resource type 24) -> requestedExecutionLevel.
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if getattr(rtype, "id", None) != 24:  # RT_MANIFEST
                continue
            for rid in getattr(getattr(rtype, "directory", None), "entries", []):
                for lang in getattr(getattr(rid, "directory", None), "entries", []):
                    try:
                        off = lang.data.struct.OffsetToData
                        size = min(lang.data.struct.Size, 65536)
                        blob = pe.get_data(off, size).decode("latin1", "ignore")
                    except Exception:
                        continue
                    m = re.search(r"requestedExecutionLevel[^>]*level\s*=\s*"
                                  r"['\"]([a-zA-Z]+)['\"]", blob)
                    if m and m.group(1).lower() in ("requireadministrator",
                                                    "highestavailable"):
                        yield Finding(
                            analyzer=self.name,
                            title=f"Manifest requests elevation ({m.group(1)})",
                            severity=Severity.LOW, category="privilege",
                            detail="The application manifest asks to run elevated; "
                                   "combined with other traits this supports a "
                                   "privilege-escalation intent. ATT&CK: T1548.002.")
                        return

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
