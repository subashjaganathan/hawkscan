"""Embedded file carving.

Scans a file's bytes for the signatures of other file formats appearing at a
non-zero offset, which is how droppers and polymorphic carriers hide a payload.
PE and ELF matches are structurally validated to avoid false hits on random
2-4 byte sequences.

When an extraction directory is provided (CLI --extract), each carved object is
written out from its offset to the next signature or end of file.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# Executable carriers where finding *another* executable embedded is expected
# (installers, archives) get a softer severity than, say, a PDF hiding a PE.
_EXECUTABLE_TYPES = {"pe", "elf", "macho"}
_CONTAINER_TYPES = {"zip", "office-ooxml", "apk", "jar", "cab", "7z", "rar", "gzip"}


def _validate_pe(data: bytes, off: int) -> bool:
    # MZ then a valid e_lfanew pointing at a "PE\0\0" signature.
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return False
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
    except struct.error:
        return False
    if not (0 < e_lfanew < 0x1000000):
        return False
    pe = off + e_lfanew
    return data[pe:pe + 4] == b"PE\x00\x00"


def _validate_elf(data: bytes, off: int) -> bool:
    return (data[off:off + 4] == b"\x7fELF"
            and off + 5 < len(data)
            and data[off + 4] in (1, 2) and data[off + 5] in (1, 2))


def _pe_size(data: bytes, off: int) -> int | None:
    """Compute an embedded PE's on-disk size from its section table, so carving
    captures the whole payload rather than stopping at a coincidental inner
    signature. Returns the byte length, or None if headers can't be read."""
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
        pe = off + e_lfanew
        num_sections = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        sect = pe + 24 + opt_size
        end = 0
        for i in range(num_sections):
            base = sect + i * 40
            raw_size = struct.unpack_from("<I", data, base + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
            end = max(end, raw_ptr + raw_size)
        return end if 0 < end <= len(data) - off else None
    except struct.error:
        return None


# (label, signature, validator-or-None)
_SIGNATURES = [
    ("PE executable", b"MZ", _validate_pe),
    ("ELF executable", b"\x7fELF", _validate_elf),
    ("ZIP archive", b"PK\x03\x04", None),
    ("PDF document", b"%PDF-", None),
    ("RAR archive", b"Rar!\x1a\x07", None),
    ("GZIP stream", b"\x1f\x8b\x08", None),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c", None),
]

_EXT_FOR = {
    "PE executable": "bin", "ELF executable": "elf", "ZIP archive": "zip",
    "PDF document": "pdf", "RAR archive": "rar", "GZIP stream": "gz",
    "7-Zip archive": "7z",
}

_MAX_REPORTED = 50


class Carver(Analyzer):
    name = "carver"

    def applies(self, ctx: AnalysisContext) -> bool:
        # Scanning text/scripts for embedded binaries is noise; skip them.
        return ctx.info.file_type not in {"text", "script"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if len(data) < 64:
            return

        raw: list[tuple[int, str]] = []
        for label, sig, validator in _SIGNATURES:
            start = 0
            while True:
                off = data.find(sig, start)
                if off == -1:
                    break
                start = off + 1
                if off == 0:
                    continue  # this is the host file's own header
                if validator and not validator(data, off):
                    continue
                raw.append((off, label))
                if len(raw) >= _MAX_REPORTED * 4:
                    break
        if not raw:
            return
        raw.sort()

        # Compute spans for validated PEs and drop any signature that falls
        # *inside* a PE (coincidental inner matches like a stray gzip header).
        pe_spans = [(o, o + (_pe_size(data, o) or 0)) for o, l in raw
                    if l == "PE executable" and _pe_size(data, o)]
        self._spans = {o: e for o, e in pe_spans}

        def nested(off: int) -> bool:
            return any(s < off < e for s, e in pe_spans)

        found = [(o, l) for o, l in raw if not nested(o)][:_MAX_REPORTED]
        if not found:
            return

        host = ctx.info.file_type
        embedded_exes = [(o, l) for o, l in found if "executable" in l]

        # A non-container, non-executable carrier hiding an executable is the
        # strongest dropper signal.
        if embedded_exes and host not in _EXECUTABLE_TYPES | _CONTAINER_TYPES:
            sev = Severity.HIGH
        elif embedded_exes:
            sev = Severity.LOW if host in _CONTAINER_TYPES else Severity.MEDIUM
        else:
            sev = Severity.INFO

        for off, label in found[:_MAX_REPORTED]:
            is_exe = "executable" in label
            yield Finding(
                analyzer=self.name,
                title=f"Embedded {label} at offset 0x{off:x}",
                severity=sev if is_exe else Severity.INFO,
                category="dropper" if is_exe else "embedded",
                detail=f"A {label} signature was found inside the file at byte {off}.",
                data={"offset": off, "type": label},
            )

        # Optional extraction.
        extract_dir = ctx.cache.get("extract_dir")
        if extract_dir:
            yield from self._extract(ctx, data, found, Path(extract_dir))

    def _extract(self, ctx, data, found, out_dir: Path) -> Iterable[Finding]:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            yield Finding(analyzer=self.name, title="Could not create extract dir",
                          severity=Severity.INFO, category="embedded", detail=str(exc))
            return
        offsets = [o for o, _ in found] + [len(data)]
        spans = getattr(self, "_spans", {})
        stem = ctx.info.path.stem
        written = 0
        for i, (off, label) in enumerate(found):
            # Prefer the structurally-computed PE size; else carve to the next
            # signature or end of file.
            end = spans.get(off) or offsets[i + 1]
            if end - off < 16:
                continue
            ext = _EXT_FOR.get(label, "bin")
            out = out_dir / f"{stem}_carved_{off:x}.{ext}"
            out.write_bytes(data[off:end])
            written += 1
        if written:
            yield Finding(
                analyzer=self.name,
                title=f"Extracted {written} embedded object(s)",
                severity=Severity.INFO, category="embedded",
                detail=f"Carved objects written to {out_dir}.",
            )
