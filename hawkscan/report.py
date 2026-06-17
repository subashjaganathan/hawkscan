"""Render a ScanResult to the terminal or JSON."""

from __future__ import annotations

import json
import sys

from .core.engine import ScanResult
from .core.findings import Severity, Verdict

# ANSI colors, disabled when output is not a TTY or on NO_COLOR.
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in __import__("os").environ


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


_VERDICT_COLOR = {
    Verdict.CLEAN: "32",            # green
    Verdict.LOW_RISK: "36",         # cyan
    Verdict.SUSPICIOUS: "33",       # yellow
    Verdict.LIKELY_MALICIOUS: "35", # magenta
    Verdict.MALICIOUS: "1;31",      # bold red
}
_SEV_COLOR = {
    Severity.INFO: "90", Severity.LOW: "36", Severity.MEDIUM: "33",
    Severity.HIGH: "31", Severity.CRITICAL: "1;31",
}


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_text(result: ScanResult, show_info: bool = False) -> str:
    info = result.info
    out: list[str] = []
    bar = "=" * 64
    out.append(bar)
    out.append(_c("  HawkScan report", "1"))
    out.append(bar)
    out.append(f"  File      : {info.path.name}")
    out.append(f"  Path      : {info.path}")
    out.append(f"  Size      : {info.size:,} bytes")
    out.append(f"  Type      : {info.description} ({info.file_type})")
    out.append(f"  Magic     : {info.magic_hex}")
    out.append(f"  SHA-256   : {info.sha256}")
    out.append(f"  MD5       : {info.md5}")
    out.append("")

    vcolor = _VERDICT_COLOR[result.verdict]
    out.append("  " + _c(f"VERDICT: {result.verdict.label.upper()}", vcolor)
               + f"   (score {result.score}, confidence {result.confidence})")
    out.append("")

    findings = sorted(result.findings, key=lambda f: -int(f.severity))
    if not show_info:
        findings = [f for f in findings if f.severity > Severity.INFO]

    if findings:
        out.append("  Evidence:")
        for f in findings:
            tag = _c(f"[{f.severity.label:8}]", _SEV_COLOR[f.severity])
            out.append(f"   {tag} ({f.analyzer}/{f.category}) {f.title}")
            if f.detail:
                out.append(f"             {_c(f.detail, '90')}")
    else:
        out.append("  No notable findings.")
    out.append("")

    meta = f"  Analyzers run: {', '.join(result.analyzers_run) or 'none'}"
    out.append(_c(meta, "90"))
    if result.analyzers_skipped:
        skipped = ", ".join(f"{k} ({v})" for k, v in result.analyzers_skipped.items())
        out.append(_c(f"  Skipped: {skipped}", "90"))
    if result.errors:
        errs = ", ".join(f"{k}: {v}" for k, v in result.errors.items()
                         if not k.endswith(":trace"))
        out.append(_c(f"  Errors: {errs}", "31"))
    out.append(_c(f"  Completed in {result.duration_ms:.0f} ms", "90"))
    out.append(bar)
    return "\n".join(out)
