"""Steganography and polyglot detection for image files.

Detects data appended after an image's real end-of-file marker (a common way to
smuggle a payload inside a valid image) and polyglot files that are
simultaneously valid as another type (image + ZIP/PDF/script). LSB
steganography is not attempted (it is not reliably detectable statically); this
focuses on the high-confidence cases: trailing data and polyglots.
"""

from __future__ import annotations

from typing import Iterable

from .base import Analyzer, AnalysisContext
from .entropy import shannon_entropy
from ..core.findings import Finding, Severity

# Second-type signatures that, embedded in an image, indicate a polyglot.
_POLYGLOT = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF", "PDF document"),
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"<?php", "PHP script"),
    (b"<script", "HTML/JS"),
    (b"#!/", "shell script"),
]


def _logical_end(data: bytes) -> int | None:
    """Return the offset just past the image's real end, or None if unknown."""
    if data[:3] == b"\xff\xd8\xff":          # JPEG
        eoi = data.rfind(b"\xff\xd9")
        return eoi + 2 if eoi != -1 else None
    if data[:8] == b"\x89PNG\r\n\x1a\n":     # PNG
        iend = data.find(b"IEND")
        return iend + 8 if iend != -1 else None  # IEND + 4-byte CRC
    if data[:4] == b"GIF8":                   # GIF
        trailer = data.rfind(b"\x3b")
        return trailer + 1 if trailer != -1 else None
    return None


class StegoAnalyzer(Analyzer):
    name = "stego"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "image"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        end = _logical_end(data)
        if end is None or end >= len(data):
            trailing = b""
        else:
            trailing = data[end:]

        if len(trailing) > 64:
            ent = shannon_entropy(trailing)
            # Appended executable/archive = payload smuggled in an image.
            if trailing[:2] == b"MZ" or trailing[:4] in (b"\x7fELF", b"PK\x03\x04"):
                yield Finding(
                    analyzer=self.name,
                    title=f"Executable/archive appended after image data "
                          f"({len(trailing):,} bytes)",
                    severity=Severity.HIGH, category="stego",
                    detail="A payload is hidden after the image's end marker.")
            else:
                yield Finding(
                    analyzer=self.name,
                    title=f"Trailing data after image end ({len(trailing):,} bytes, "
                          f"entropy {ent:.2f})",
                    severity=Severity.MEDIUM if ent >= 7.0 else Severity.LOW,
                    category="stego",
                    detail="Data after the image's real EOF; possible steganography "
                           "or appended payload.")

        # Polyglot: a second file-type signature embedded past the header.
        body = data[16:]
        for sig, label in _POLYGLOT:
            idx = body.find(sig)
            if idx != -1:
                yield Finding(
                    analyzer=self.name,
                    title=f"Polyglot: embedded {label} signature",
                    severity=Severity.MEDIUM, category="polyglot",
                    detail=f"Image also contains a {label} signature at offset "
                           f"{idx + 16}; polyglots are used to smuggle content.")
                break
