"""Tests for file identification, scoring, and engine orchestration."""

from __future__ import annotations

import hashlib

import pytest

from hawk_malware_scan.core import fileinfo
from hawk_malware_scan.core.engine import Engine, CATEGORY_SCORE_CAP
from hawk_malware_scan.core.findings import Verdict, Severity, score_to_verdict


# ---- type detection -----------------------------------------------------

@pytest.mark.parametrize("head,ext,expected_type", [
    (b"MZ\x90\x00", ".exe", "pe"),
    (b"\x7fELF\x02\x01\x01\x00", ".so", "elf"),
    (b"%PDF-1.7", ".pdf", "pdf"),
    (b"PK\x03\x04", ".zip", "zip"),
    (b"PK\x03\x04", ".docx", "office-ooxml"),
    (b"Hello world, just text.", ".txt", "text"),
    (b"\x00\x01\x02\x03\xff\xfe", ".bin", "data"),
])
def test_detect_type(head, ext, expected_type):
    ftype, _ = fileinfo.detect_type(head, ext)
    assert ftype == expected_type


def test_cafebabe_class_not_macho():
    # 0xCAFEBABE collides between Mach-O fat and Java .class; extension decides.
    ftype, _ = fileinfo.detect_type(b"\xca\xfe\xba\xbe\x00\x00\x00\x34", ".class")
    assert ftype == "java-class"
    ftype, _ = fileinfo.detect_type(b"\xca\xfe\xba\xbe\x00\x00\x00\x02", ".bin")
    assert ftype == "macho"


def test_inspect_hashes_and_mismatch(tmp_path):
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # PE content, image extension
    info = fileinfo.inspect(f)
    assert info.sha256 == hashlib.sha256(f.read_bytes()).hexdigest()
    assert info.file_type == "pe"
    assert info.ext_mismatch is True


# ---- scoring ------------------------------------------------------------

@pytest.mark.parametrize("score,verdict", [
    (0, Verdict.CLEAN),
    (14, Verdict.CLEAN),
    (15, Verdict.LOW_RISK),
    (45, Verdict.SUSPICIOUS),
    (90, Verdict.LIKELY_MALICIOUS),
    (150, Verdict.MALICIOUS),
    (10_000, Verdict.MALICIOUS),
])
def test_score_to_verdict(score, verdict):
    assert score_to_verdict(score) == verdict


# ---- engine -------------------------------------------------------------

def test_benign_text_is_clean(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("This is a perfectly ordinary note about lunch.\n")
    res = Engine().scan(f)
    assert res.verdict == Verdict.CLEAN


def test_allowlist_short_circuits(tmp_path):
    f = tmp_path / "evil.ps1"
    f.write_text("powershell -w hidden -enc IEX(New-Object Net.WebClient)")
    sha = fileinfo.inspect(f).sha256

    eng = Engine()
    eng.allowlist = {sha}  # simulate a known-good entry
    res = eng.scan(f)
    assert res.verdict == Verdict.CLEAN
    assert any(x.category == "allowlist" for x in res.findings)


def test_oversized_file_skips_deep_analysis(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"\x00" * 2048)
    eng = Engine(max_scan_size=1024)  # 1 KiB cap, file is 2 KiB
    res = eng.scan(f)
    assert "engine" not in res.analyzers_run
    assert any("too large" in x.title.lower() for x in res.findings)


def test_category_cap_limits_runaway_score():
    from hawk_malware_scan.core.findings import Finding
    # 10 high (50) findings of one category = raw 500, capped to CATEGORY_SCORE_CAP.
    findings = [Finding(analyzer="x", title=f"f{i}", severity=Severity.HIGH,
                        category="execution") for i in range(10)]
    raw, capped = Engine._score(findings)
    assert raw == 500
    assert capped == CATEGORY_SCORE_CAP


def test_denylist_forces_malicious(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"harmless content")
    sha = fileinfo.inspect(f).sha256
    eng = Engine()
    eng.denylist = {sha}
    res = eng.scan(f)
    assert res.verdict == Verdict.MALICIOUS
    assert any(x.category == "denylist" for x in res.findings)


def test_parallel_scan_preserves_order(tmp_path):
    from hawk_malware_scan.cli import _scan_files
    files = []
    for i in range(6):
        p = tmp_path / f"f{i}.txt"
        p.write_text(f"file number {i}")
        files.append(p)
    out = _scan_files(Engine(), files, jobs=4)
    assert [o[0] for o in out] == files          # order preserved
    assert all(err is None for _, _, err in out)  # all scanned ok


def test_dedup_drops_identical_findings():
    from hawk_malware_scan.core.findings import Finding
    a = Finding(analyzer="x", title="same", severity=Severity.HIGH, category="c")
    b = Finding(analyzer="x", title="same", severity=Severity.HIGH, category="c")
    out = Engine._dedup([a, b])
    assert len(out) == 1
