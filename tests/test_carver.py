"""Tests for embedded file carving."""

from __future__ import annotations

import struct

from hawk_malware_scan.core import fileinfo
from hawk_malware_scan.analyzers.base import AnalysisContext
from hawk_malware_scan.analyzers.carver import Carver, _pe_size, _validate_pe


def _min_pe() -> bytes:
    """Construct a minimal but structurally valid PE with one section."""
    sig_off = 0x40
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, sig_off)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 0, 0)
    raw_ptr = sig_off + len(coff) + 40
    raw_size = 16
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 16, raw_size)
    struct.pack_into("<I", sec, 20, raw_ptr)
    body = bytes(dos) + coff + bytes(sec)
    body += b"\x00" * (raw_ptr - len(body)) + b"X" * raw_size
    return body


def test_pe_size_and_validation():
    pe = _min_pe()
    assert _validate_pe(pe, 0)
    assert _pe_size(pe, 0) == len(pe)


def test_carver_detects_embedded_pe_in_carrier(tmp_path):
    pe = _min_pe()
    carrier = tmp_path / "decoy.pdf"
    carrier.write_bytes(b"%PDF-1.5\n decoy \n" + b"A" * 100 + pe)
    ctx = AnalysisContext(info=fileinfo.inspect(carrier), content=carrier.read_bytes())

    findings = list(Carver().analyze(ctx))
    exe = [f for f in findings if f.category == "dropper"]
    assert exe, "embedded PE should be flagged as a dropper"
    assert exe[0].severity.name == "HIGH"  # PE hidden in a non-executable carrier


def test_carver_extracts_full_pe(tmp_path):
    pe = _min_pe()
    carrier = tmp_path / "decoy.pdf"
    carrier.write_bytes(b"%PDF-1.5\n" + b"A" * 50 + pe)
    out = tmp_path / "out"
    ctx = AnalysisContext(info=fileinfo.inspect(carrier), content=carrier.read_bytes())
    ctx.cache["extract_dir"] = str(out)

    list(Carver().analyze(ctx))
    carved = list(out.glob("*"))
    assert carved, "a carved file should be written"
    # The carved PE should be the full computed size, not truncated.
    assert any(c.read_bytes()[:2] == b"MZ" and len(c.read_bytes()) == len(pe)
               for c in carved)
