"""'.NET' (managed PE) metadata analysis.

A large share of modern Windows malware is .NET. This analyzer locates the CLR
metadata in a managed PE and parses the #US (user strings) and #Strings
(type/method names) heaps directly, recovering the literal strings the IL uses -
URLs, commands, mutexes - which are the real behavioural indicators. Pure
struct parsing on top of pefile; no dnlib/.NET runtime needed.
"""

from __future__ import annotations

import re
import struct
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

try:
    import pefile  # type: ignore
    _HAVE_PEFILE = True
except Exception:
    _HAVE_PEFILE = False

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)
_SUSPICIOUS = [
    (re.compile(r"powershell|cmd\.exe|Invoke-Expression|FromBase64String", re.I),
     "Command/exec string in IL", Severity.HIGH, "execution"),
    (re.compile(r"DownloadString|DownloadData|WebClient|HttpClient", re.I),
     "Network download string in IL", Severity.MEDIUM, "network"),
    (re.compile(r"CurrentVersion\\\\Run|schtasks|StartupPath", re.I),
     "Persistence string in IL", Severity.MEDIUM, "persistence"),
    (re.compile(r"Mutex|Global\\\\", re.I),
     "Mutex string in IL", Severity.LOW, "config"),
    (re.compile(r"VirtualProtect|CreateThread|InjectAssembly|Assembly\.Load", re.I),
     "Reflection/injection string in IL", Severity.MEDIUM, "injection"),
]


class DotNetAnalyzer(Analyzer):
    name = "dotnet"

    def applies(self, ctx: AnalysisContext) -> bool:
        return _HAVE_PEFILE and ctx.info.file_type == "pe"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            pe = pefile.PE(data=ctx.read_all(), fast_load=True)
        except Exception:
            return
        com_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_idx]
        if not com.VirtualAddress:
            return  # not a managed assembly

        user_strings, names = self._parse_metadata(pe, com)
        if user_strings is None:
            yield Finding(analyzer=self.name, title=".NET managed assembly",
                          severity=Severity.INFO, category="format",
                          detail="CLR metadata present but could not be parsed.")
            return

        yield Finding(
            analyzer=self.name,
            title=f".NET assembly ({len(user_strings)} IL string(s))",
            severity=Severity.INFO, category="format",
            detail="Managed (.NET) PE; IL user strings recovered for analysis.")

        blob = "\n".join(user_strings)
        seen: set[str] = set()
        for pattern, title, sev, cat in _SUSPICIOUS:
            m = pattern.search(blob)
            if m and title not in seen:
                seen.add(title)
                yield Finding(analyzer=self.name, title=title, severity=sev,
                              category=cat, detail=f"IL string: {m.group()[:60]!r}")

        urls = sorted(set(_URL_RE.findall(blob)))[:15]
        if urls:
            yield Finding(analyzer=self.name,
                          title=f"{len(urls)} URL(s) in .NET IL strings",
                          severity=Severity.INFO, category="network",
                          detail="; ".join(urls[:8]), data={"urls": urls})

        # Obfuscator hint: many GUID-like or single-char type names.
        if names:
            short = sum(1 for n in names if len(n) <= 2)
            if names and short / len(names) > 0.5 and len(names) > 20:
                yield Finding(analyzer=self.name,
                              title="Likely .NET obfuscation (renamed symbols)",
                              severity=Severity.MEDIUM, category="obfuscation",
                              detail="Most type/method names are 1-2 chars "
                                     "(ConfuserEx/Obfuscar-style renaming).")

    # ---- metadata parsing ----------------------------------------------
    def _parse_metadata(self, pe, com):
        try:
            cor20 = pe.get_data(com.VirtualAddress, max(com.Size, 72))
            meta_rva, meta_size = struct.unpack_from("<II", cor20, 8)
            md = pe.get_data(meta_rva, meta_size)
            if struct.unpack_from("<I", md, 0)[0] != 0x424A5342:  # 'BSJB'
                return None, None
            ver_len = struct.unpack_from("<I", md, 12)[0]
            off = 16 + ((ver_len + 3) & ~3)
            off += 2  # flags
            nstreams = struct.unpack_from("<H", md, off)[0]
            off += 2
            streams: dict[str, tuple[int, int]] = {}
            for _ in range(nstreams):
                s_off, s_size = struct.unpack_from("<II", md, off)
                off += 8
                end = md.index(b"\x00", off)
                name = md[off:end].decode("ascii", "ignore")
                off += ((end - off + 1) + 3) & ~3
                streams[name] = (s_off, s_size)
        except Exception:
            return None, None

        user_strings = self._parse_us(md, streams.get("#US"))
        names = self._parse_strings(md, streams.get("#Strings"))
        return user_strings, names

    @staticmethod
    def _parse_us(md: bytes, loc) -> list[str]:
        if not loc:
            return []
        start, size = loc
        heap = md[start:start + size]
        out: list[str] = []
        pos = 1  # first byte is an empty blob
        while pos < len(heap) and len(out) < 5000:
            b0 = heap[pos]
            if b0 & 0x80 == 0:
                length, pos = b0, pos + 1
            elif b0 & 0xC0 == 0x80:
                length = ((b0 & 0x3F) << 8) | heap[pos + 1]; pos += 2
            else:
                length = ((b0 & 0x1F) << 24) | (heap[pos + 1] << 16) | \
                         (heap[pos + 2] << 8) | heap[pos + 3]; pos += 4
            if length <= 0:
                continue
            raw = heap[pos:pos + length - 1]  # last byte is a flag
            pos += length
            s = raw.decode("utf-16le", "ignore").strip("\x00")
            if s and any(32 <= ord(c) < 127 for c in s):
                out.append(s)
        return out

    @staticmethod
    def _parse_strings(md: bytes, loc) -> list[str]:
        if not loc:
            return []
        start, size = loc
        heap = md[start:start + size]
        return [p.decode("utf-8", "ignore") for p in heap.split(b"\x00")
                if 1 <= len(p) <= 100][:5000]
