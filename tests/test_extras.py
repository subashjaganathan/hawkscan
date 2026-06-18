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


def test_hashdb_loader(tmp_path, monkeypatch):
    from hawkscan.core import engine
    db = tmp_path / "hashdb.txt"
    db.write_text("a" * 64 + " EvilFamily\n" + "b" * 64 + "\n# comment\n")
    monkeypatch.setattr(engine, "_HASHDB_PATH", db)
    loaded = engine._load_hashdb(db)
    assert loaded["a" * 64] == "EvilFamily"
    assert loaded["b" * 64] == "malicious"  # default label
