"""Script analysis: PowerShell, batch, VBScript, JS, shell, etc.

Scores obfuscation and high-risk constructs. The StringsAnalyzer already
catches many command primitives; this adds script-specific obfuscation metrics
(concatenation density, char-code arrays, base64 blob ratio).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_CHAR_ARRAY = re.compile(r"(?:chr\(\d+\)\s*[&+]\s*){4,}", re.I)
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:%[0-9a-fA-F]{2}){6,}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class ScriptAnalyzer(Analyzer):
    name = "script"

    # Extensions that are unambiguously scripts. Plain ".txt"/".log" are
    # intentionally excluded: running obfuscation heuristics on arbitrary text
    # produced false positives (a log line with a long base64 token, etc.).
    _SCRIPT_EXTS = {
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".hta", ".sh", ".py", ".pl", ".rb", ".php",
    }

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "script" or ctx.info.extension in self._SCRIPT_EXTS

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            text = ctx.read_all().decode("utf-8", "ignore")
        except Exception:
            return
        if not text.strip():
            return

        lowered = text.lower()

        # Microsoft Script Encoder (VBE/JSE) encoded content. Its #@~^ marker is
        # a strong malicious signal - legitimate scripts almost never use it now.
        if "#@~^" in text:
            yield Finding(
                analyzer=self.name,
                title="Encoded script (Microsoft Script Encoder VBE/JSE)",
                severity=Severity.HIGH,
                category="obfuscation",
                detail="Contains the #@~^ encoder marker; the real logic is hidden "
                       "behind reversible script encoding.",
            )

        # Large base64 blobs embedded in a script = staged payload.
        blobs = _B64_BLOB.findall(text)
        if blobs:
            longest = max(len(b) for b in blobs)
            yield Finding(
                analyzer=self.name,
                title=f"Embedded base64 blob ({longest} chars)",
                severity=Severity.MEDIUM if longest > 400 else Severity.LOW,
                category="obfuscation",
                detail="Large base64 strings commonly carry an encoded payload.",
            )

        if _CHAR_ARRAY.search(text):
            yield Finding(
                analyzer=self.name,
                title="Character-code string construction",
                severity=Severity.MEDIUM,
                category="obfuscation",
                detail="Chr()/char-code concatenation hides literal strings.",
            )

        if _HEX_ESCAPES.search(text):
            yield Finding(
                analyzer=self.name,
                title="Dense hex/percent escaping",
                severity=Severity.MEDIUM,
                category="obfuscation",
                detail="Long runs of \\xNN or %NN escapes obscure the real content.",
            )

        # Concatenation density (PowerShell '+'.join style obfuscation).
        if len(text) > 200:
            plus_ratio = text.count("+") / len(text)
            backtick_ratio = text.count("`") / len(text)
            if plus_ratio > 0.03 or backtick_ratio > 0.02:
                yield Finding(
                    analyzer=self.name,
                    title="High operator density (string-splitting obfuscation)",
                    severity=Severity.MEDIUM,
                    category="obfuscation",
                    detail="Excessive '+'/backtick use is typical of obfuscated "
                           "PowerShell/JS.",
                )

        # Dynamic-eval constructs by language. (label, severity). Generic eval()/
        # Execute() are common in legitimate code (e.g. Python stdlib), so they
        # are LOW; PowerShell/WScript download-and-run primitives stay HIGH.
        eval_markers = {
            "iex": ("PowerShell Invoke-Expression", Severity.HIGH),
            "invoke-expression": ("PowerShell Invoke-Expression", Severity.HIGH),
            "wscript.shell": ("WScript.Shell command execution", Severity.HIGH),
            "frombase64string": ("Base64 decode-and-run", Severity.HIGH),
            "eval(": ("eval() dynamic execution", Severity.LOW),
            "execute(": ("VBScript Execute", Severity.LOW),
            "executeglobal": ("VBScript ExecuteGlobal", Severity.MEDIUM),
        }
        for marker, (label, sev) in eval_markers.items():
            if marker in lowered:
                yield Finding(
                    analyzer=self.name,
                    title=label,
                    severity=sev,
                    category="execution",
                    detail=f"Script contains {marker!r}.",
                )

        # One-line scripts with very high entropy = heavily obfuscated.
        if len(text) > 500 and text.count("\n") < 3 and _entropy(text) > 5.2:
            yield Finding(
                analyzer=self.name,
                title="Single-line high-entropy script",
                severity=Severity.MEDIUM,
                category="obfuscation",
                detail="Minified, high-entropy one-liner; typical of dropper stagers.",
            )
