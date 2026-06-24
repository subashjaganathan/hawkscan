"""Tests for signature verification, web-UI upload parsing, AI gating, hash DB."""

from __future__ import annotations

from hawkscan.intel import sigcheck
from hawkscan import ai, webui, vt


def test_sigcheck_returns_known_status():
    status, _ = sigcheck.verify(__file__)  # a text file: never a valid PE sig
    assert status in {"valid", "invalid", "unsigned", "unknown"}


def test_ai_gating_reports_reason():
    ok, why = ai.available()
    assert isinstance(ok, bool)
    if not ok:
        assert why  # explains why it's unavailable


def test_ai_summarize_degrades_without_backend():
    out = ai.summarize({"verdict": "Clean"})
    # Without anthropic/key it returns a bracketed note, never raises.
    assert out.startswith("[AI summary")


def test_webui_safe_name_blocks_traversal():
    assert webui.safe_name("../../../etc/passwd") == "passwd"
    assert webui.safe_name(r"..\..\windows\system32\evil.dll") == "evil.dll"
    assert webui.safe_name("") == "upload.bin"
    assert webui.safe_name(None) == "upload.bin"
    safe = webui.safe_name("normal.exe")
    assert "/" not in safe and "\\" not in safe and ".." not in safe


def test_config_defaults_and_thresholds():
    from hawkscan.core import config
    t = config.thresholds()
    assert t["suspicious"] == 45 and t["malicious"] == 150
    assert config.category_cap() == 120


def test_webui_multipart_parse():
    boundary = "X"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="a.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        "HELLO\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    name, content = webui._parse_upload(
        f"multipart/form-data; boundary={boundary}", body)
    assert name == "a.bin"
    assert content == b"HELLO"


def test_vt_gating_and_degradation(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    ok, why = vt.available()
    assert ok is False and "VT_API_KEY" in why
    # Lookup never raises without a key; returns a structured error.
    res = vt.lookup_hash("a" * 64)
    assert res["found"] is False and res["error"]


def test_dotnet_user_string_parser():
    from hawkscan.analyzers.dotnet_analyzer import DotNetAnalyzer
    # #US heap: leading empty blob (0x00), then "hi" as UTF-16LE + flag byte.
    # blob length = 4 (utf-16 'hi') + 1 flag = 5 -> single compressed byte 0x05.
    heap = b"\x00" + b"\x05" + "hi".encode("utf-16le") + b"\x00"
    md = b"PAD" + heap
    out = DotNetAnalyzer._parse_us(md, (3, len(heap)))
    assert "hi" in out


def test_hashdb_loader(tmp_path, monkeypatch):
    from hawkscan.core import engine
    db = tmp_path / "hashdb.txt"
    db.write_text("a" * 64 + " EvilFamily\n" + "b" * 64 + "\n# comment\n")
    monkeypatch.setattr(engine, "_HASHDB_PATH", db)
    loaded = engine._load_hashdb(db)
    assert loaded["a" * 64] == "EvilFamily"
    assert loaded["b" * 64] == "malicious"  # default label


def test_dotnet_capability_detection():
    from hawkscan.analyzers.dotnet_analyzer import DotNetAnalyzer
    a = DotNetAnalyzer()
    # Native-injection P/Invoke (>=2 APIs) + embedded PowerShell host.
    fnds = list(a._dotnet_capabilities(
        ["VirtualAllocEx", "CreateRemoteThread", "WriteProcessMemory"],
        "System.Management.Automation"))
    titles = [f.title for f in fnds]
    assert any("Native injection P/Invoke" in t for t in titles)
    assert any("Embedded PowerShell host" in t for t in titles)
    # Known protector marker.
    prot = list(a._dotnet_capabilities(["x"], "ConfusedByAttribute"))
    assert any("ConfuserEx" in f.title for f in prot)
    # Clean symbol set must not raise injection/exec findings.
    clean = list(a._dotnet_capabilities(
        ["Program", "Main", "Console", "WriteLine"], "hello world"))
    assert not any(f.category in ("injection", "execution") for f in clean)


def test_emulate_degrades_without_engines():
    from hawkscan.analyzers.emulate import EmulateAnalyzer
    ok = EmulateAnalyzer.is_available()
    assert isinstance(ok, bool)
    if not ok:
        assert EmulateAnalyzer.unavailable_reason  # explains how to enable


def test_emulate_floss_json_parser():
    from hawkscan.analyzers.emulate import EmulateAnalyzer
    # FLOSS v3-style JSON.
    data = {"strings": {
        "decoded_strings": [{"string": "http://evil-emu.com/gate"}],
        "stack_strings": [{"string": "powershell -enc AAAA"}],
        "tight_strings": ["cmd.exe /c whoami"],
        "static_strings": [{"string": "ignored-static"}],
    }}
    got = EmulateAnalyzer._collect_floss_strings(data)
    assert "http://evil-emu.com/gate" in got
    assert "powershell -enc AAAA" in got
    assert "cmd.exe /c whoami" in got
    assert "ignored-static" not in got  # static set excluded


def test_emulate_speakeasy_report_parsers():
    from hawkscan.analyzers.emulate import EmulateAnalyzer
    report = {"entry_points": [{
        "apis": [{"api_name": "kernel32.WriteProcessMemory"},
                 {"api_name": "wininet.InternetConnectA"}],
        "network_events": {"dns": [{"query": "c2.example.bad"}],
                           "traffic": [{"server": "45.77.88.99"}]},
    }]}
    apis = EmulateAnalyzer._report_apis(report)
    assert "kernel32.WriteProcessMemory" in apis
    hosts = EmulateAnalyzer._report_network(report)
    assert "c2.example.bad" in hosts and "45.77.88.99" in hosts
