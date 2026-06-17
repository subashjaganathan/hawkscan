"""Tests for RTF analysis, binary runtime profiling, and IOC whitelisting."""

from __future__ import annotations

from hawkscan.core import fileinfo
from hawkscan.analyzers.base import AnalysisContext
from hawkscan.analyzers.rtf_analyzer import RTFAnalyzer
from hawkscan.analyzers.binprofile import BinProfileAnalyzer
from hawkscan.analyzers.strings_analyzer import _is_whitelisted


def _ctx(tmp_path, name, data, strings=None):
    f = tmp_path / name
    f.write_bytes(data)
    ctx = AnalysisContext(info=fileinfo.inspect(f), content=data)
    if strings is not None:
        ctx.cache["strings"] = strings
    return ctx


def test_rtf_detected_and_equation_exploit_flagged(tmp_path):
    rtf = (rb"{\rtf1\ansi{\object\objemb\objupdate"
           rb"{\*\objclass Equation.3}{\*\objdata 0105" + b"41" * 512 + rb"}}}")
    ctx = _ctx(tmp_path, "x.rtf", rtf)
    assert ctx.info.file_type == "rtf"
    titles = [f.title for f in RTFAnalyzer().analyze(ctx)]
    assert any("Equation Editor" in t for t in titles)
    assert any("objupdate" in t for t in titles)


def test_binprofile_detects_go(tmp_path):
    ctx = _ctx(tmp_path, "g.exe", b"MZ" + b"\x00" * 64,
               strings=["Go build ID: abc", "go1.21", "runtime.goexit"])
    labels = [f.data.get("runtime") for f in BinProfileAnalyzer().analyze(ctx)]
    assert "Go" in labels


def test_binprofile_detects_dotnet(tmp_path):
    ctx = _ctx(tmp_path, "n.exe", b"MZ" + b"\x00" * 64,
               strings=["mscoree.dll", "_CorExeMain", "mscorlib"])
    labels = [f.data.get("runtime") for f in BinProfileAnalyzer().analyze(ctx)]
    assert ".NET / managed" in labels


def test_onenote_detected_with_embedded_object(tmp_path):
    from hawkscan.analyzers.office_analyzer import OfficeAnalyzer
    one = (b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
           + b"\x00" * 32 + b"\xe7\x16\xe3\xbd\x65\x26\x11\x45" + b"MZ")
    ctx = _ctx(tmp_path, "n.one", one)
    assert ctx.info.file_type == "onenote"
    titles = [f.title for f in OfficeAnalyzer().analyze(ctx)]
    assert any("OneNote embedded file" in t for t in titles)


def test_ioc_whitelist():
    assert _is_whitelisted("http://schemas.microsoft.com/office")
    assert _is_whitelisted("http://www.w3.org/2000/svg")
    assert not _is_whitelisted("http://evil-c2-domain.tk/payload")


def test_email_phishing_indicators(tmp_path):
    import base64
    from hawkscan.analyzers.email_analyzer import EmailAnalyzer
    pe_b64 = base64.b64encode(b"MZ" + b"\x90" * 32).decode()
    eml = (
        'From: "Bank" <help@bank.com>\n'
        "Return-Path: <attacker@evil.ru>\n"
        "MIME-Version: 1.0\n"
        "Authentication-Results: mx; spf=fail; dmarc=fail\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nopen it\n"
        "--B\nContent-Type: application/octet-stream; name=\"doc.pdf.exe\"\n"
        "Content-Transfer-Encoding: base64\n"
        'Content-Disposition: attachment; filename="doc.pdf.exe"\n\n'
        f"{pe_b64}\n--B--\n"
    ).encode()
    ctx = _ctx(tmp_path, "p.eml", eml)
    assert ctx.info.file_type == "email"
    titles = [f.title for f in EmailAnalyzer().analyze(ctx)]
    assert any("SPF" in t for t in titles)
    assert any("Double-extension" in t for t in titles)
    assert any("Return-Path" in t for t in titles)
