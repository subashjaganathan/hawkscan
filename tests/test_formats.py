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


def test_ioc_whitelist():
    assert _is_whitelisted("http://schemas.microsoft.com/office")
    assert _is_whitelisted("http://www.w3.org/2000/svg")
    assert not _is_whitelisted("http://evil-c2-domain.tk/payload")
