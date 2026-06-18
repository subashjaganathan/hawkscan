"""Optional AI summary of a scan report (opt-in, requires network + a key).

This is the only part of HawkScan that can reach the network. It sends the
structured (non-binary) scan report to the Claude API and returns a short
plain-language analyst summary. Disabled unless both the `anthropic` package is
installed and ANTHROPIC_API_KEY is set, so the offline core is never affected.
"""

from __future__ import annotations

import json
import os

# Latest capable Claude model at time of writing.
_MODEL = "claude-opus-4-8"

_SYSTEM = (
    "You are a malware-triage analyst. Given a JSON static-analysis report, write "
    "a concise (4-8 sentence) plain-language summary: the likely verdict and why, "
    "the most important evidence, notable capabilities/ATT&CK techniques, and a "
    "clear recommended next step. Do not invent findings beyond the report."
)


def available() -> tuple[bool, str]:
    try:
        import anthropic  # noqa: F401
    except Exception:
        return False, "the 'anthropic' package is not installed (pip install anthropic)"
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False, "ANTHROPIC_API_KEY is not set"
    return True, ""


def summarize(report: dict) -> str:
    ok, why = available()
    if not ok:
        return f"[AI summary unavailable: {why}]"
    import anthropic

    client = anthropic.Anthropic()
    # Trim the report so we don't send huge string dumps.
    trimmed = dict(report)
    trimmed.pop("dynamic", None)
    payload = json.dumps(trimmed)[:12000]
    try:
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=600,
            system=_SYSTEM,
            messages=[{"role": "user", "content":
                       f"Summarize this HawkScan report:\n{payload}"}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    except Exception as exc:
        return f"[AI summary failed: {exc}]"
