"""Tests for the dynamic-analysis safety gate.

These tests never execute a sample. They verify the refusal logic and command
mapping only, so the suite is safe to run anywhere (including CI).
"""

from __future__ import annotations

from pathlib import Path

from hawkscan.dynamic import sandbox, SANDBOX_ENV_FLAG


def test_refuses_without_sandbox_env(tmp_path, monkeypatch):
    monkeypatch.delenv(SANDBOX_ENV_FLAG, raising=False)
    sample = tmp_path / "x.ps1"
    sample.write_text("Write-Host hi")
    res = sandbox.run_sample(sample, "script", allow_detonate=True)
    assert res.ran is False
    assert "HAWKSCAN_SANDBOX" in res.skipped_reason


def test_refuses_without_detonate_flag(tmp_path, monkeypatch):
    monkeypatch.setenv(SANDBOX_ENV_FLAG, "1")
    sample = tmp_path / "x.ps1"
    sample.write_text("Write-Host hi")
    res = sandbox.run_sample(sample, "script", allow_detonate=False)
    assert res.ran is False
    assert "detonate" in res.skipped_reason


def test_no_runner_for_unknown_type(tmp_path, monkeypatch):
    monkeypatch.setenv(SANDBOX_ENV_FLAG, "1")
    sample = tmp_path / "x.unknownext"
    sample.write_bytes(b"\x00\x01")
    res = sandbox.run_sample(sample, "data", allow_detonate=True)
    assert res.ran is False
    assert "no runner" in res.skipped_reason


def test_command_mapping():
    assert sandbox._build_command(Path("a.ps1"), "script")[0] == "powershell"
    assert sandbox._build_command(Path("a.py"), "script")[-1].endswith("a.py")
    assert sandbox._build_command(Path("a.txt"), "text") is None


def test_method_resolution():
    # Android always routes to adb; an explicit method passes through.
    assert sandbox._resolve_method("auto", "apk") == "adb"
    assert sandbox._resolve_method("monitor", "pe") == "monitor"
    assert sandbox._resolve_method("frida", "pe") == "frida"


def test_tracers_expose_availability():
    from hawkscan.dynamic import strace_tracer, frida_tracer, adb_tracer
    # available() must be callable and return a bool without side effects.
    assert isinstance(strace_tracer.available(), bool)
    assert isinstance(frida_tracer.available(), bool)
    assert isinstance(adb_tracer.available(), bool)


def test_frida_trace_reports_missing_dependency_cleanly():
    # With frida absent, trace() returns a note rather than raising.
    from hawkscan.dynamic import frida_tracer
    if not frida_tracer.available():
        out = frida_tracer.trace(["whatever"], timeout=1)
        assert out["notes"] and "frida" in out["notes"][0].lower()
