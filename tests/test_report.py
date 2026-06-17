"""Smoke tests for the text and HTML report renderers."""

from __future__ import annotations

from hawkscan.core.engine import Engine
from hawkscan import report, report_html


def test_html_report_is_self_contained(tmp_path):
    f = tmp_path / "evil.ps1"
    f.write_text("powershell -w hidden -enc AAAA; IEX(New-Object Net.WebClient)")
    res = Engine().scan(f)

    out = report_html.render_html([res])
    assert out.startswith("<!doctype html>")
    assert "HawkScan Report" in out
    assert res.verdict.label.upper() in out
    # No external assets or network references.
    assert "http://" not in out and "https://" not in out


def test_text_report_contains_verdict(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("ordinary content")
    res = Engine().scan(f)
    text = report.render_text(res)
    assert "VERDICT" in text
    assert res.verdict.label.upper() in text
