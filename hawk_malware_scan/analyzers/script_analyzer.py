"""Script analysis: PowerShell, batch, VBScript, JS/JSE, HTA, WSF, shell, etc.

Two layers of analysis run here:

  1. Obfuscation metrics on the raw text (encoder markers, base64 blobs,
     char-code construction, escape density, entropy) - quick "is this hidden?"
     signals.
  2. A behavioural engine that first *deobfuscates* the script (PowerShell
     -EncodedCommand, FromBase64String, char-array joins, plus the shared JS/VBS
     deobfuscator) and then matches the recovered text against an original
     indicator database mapped to MITRE ATT&CK techniques: download cradles,
     dynamic execution, AMSI/ETW/logging evasion, persistence, process
     injection, credential access, discovery and anti-analysis.

The behavioural pass is what turns "large obfuscated script" into a concrete
account of *what the script actually does*, and recovers the embedded IOCs.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from typing import Iterable

from .base import Analyzer, AnalysisContext
from .deobfuscate import DeobAnalyzer
from ..core.findings import Finding, Severity

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_CHAR_ARRAY = re.compile(r"(?:chr\(\d+\)\s*[&+]\s*){4,}", re.I)
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:%[0-9a-fA-F]{2}){6,}")

# PowerShell -EncodedCommand / -enc / -e <base64> (the value is UTF-16LE base64).
_PS_ENC = re.compile(
    r"-e(?:nc(?:odedcommand)?)?\b\s+([A-Za-z0-9+/=]{16,})", re.I)
# .NET FromBase64String("...") literal payloads.
_FROMB64 = re.compile(r"FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]", re.I)
# [char[]] / char-code join arrays: 104,116,116,112 ... -join
_CHARJOIN = re.compile(r"(?:\(?\s*(?:\[char\])?\s*)?((?:\d{1,3}\s*,\s*){5,}\d{1,3})")

# IOC extraction (recovered into finding.data so the report/deob surface them).
_URL_RE = re.compile(r"https?://[^\s\"'<>)\\]{4,300}", re.I)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Behavioural indicator database (original). Each entry:
#   (substring-or-regex, is_regex, title, severity, category, attack_id)
_INDICATORS: list[tuple[str, bool, str, Severity, str, str]] = [
    # --- download / ingress (T1105) ---
    ("downloadstring", False, "Download-and-execute cradle (DownloadString)", Severity.HIGH, "download", "T1105"),
    ("downloadfile", False, "Downloads a file to disk", Severity.HIGH, "download", "T1105"),
    ("downloaddata", False, "Downloads remote data", Severity.HIGH, "download", "T1105"),
    ("net.webclient", False, "Uses .NET WebClient for retrieval", Severity.MEDIUM, "download", "T1105"),
    ("invoke-webrequest", False, "Invoke-WebRequest network fetch", Severity.MEDIUM, "download", "T1105"),
    (r"\biwr\b", True, "Invoke-WebRequest (iwr) network fetch", Severity.MEDIUM, "download", "T1105"),
    ("start-bitstransfer", False, "BITS transfer (stealthy download)", Severity.HIGH, "download", "T1197"),
    ("msxml2.xmlhttp", False, "MSXML2.XMLHTTP download object", Severity.HIGH, "download", "T1105"),
    ("winhttp.winhttprequest", False, "WinHTTP request object", Severity.MEDIUM, "download", "T1105"),
    ("urldownloadtofile", False, "URLDownloadToFile API", Severity.HIGH, "download", "T1105"),
    ("certutil", False, "certutil abuse (download/decode)", Severity.HIGH, "download", "T1105"),
    ("bitsadmin", False, "bitsadmin abuse (download)", Severity.HIGH, "download", "T1197"),
    # --- dynamic execution (T1059) ---
    ("invoke-expression", False, "PowerShell Invoke-Expression (dynamic exec)", Severity.HIGH, "execution", "T1059.001"),
    (r"\biex\b", True, "PowerShell IEX (dynamic exec)", Severity.HIGH, "execution", "T1059.001"),
    ("wscript.shell", False, "WScript.Shell command execution", Severity.HIGH, "execution", "T1059.005"),
    ("shellexecute", False, "ShellExecute process launch", Severity.MEDIUM, "execution", "T1059"),
    ("executeglobal", False, "VBScript ExecuteGlobal", Severity.HIGH, "execution", "T1059.005"),
    ("mshta", False, "mshta script execution (LOLBin)", Severity.HIGH, "execution", "T1218.005"),
    ("regsvr32", False, "regsvr32 execution (LOLBin)", Severity.HIGH, "execution", "T1218.010"),
    ("rundll32", False, "rundll32 execution (LOLBin)", Severity.HIGH, "execution", "T1218.011"),
    ("start-process", False, "Start-Process launch", Severity.LOW, "execution", "T1059.001"),
    ("frombase64string", False, "Base64 decode for in-memory execution", Severity.HIGH, "execution", "T1140"),
    # --- defense evasion (T1562 / T1027 / T1059.001) ---
    ("amsiutils", False, "AMSI bypass (AmsiUtils reflection)", Severity.HIGH, "evasion", "T1562.001"),
    ("amsiinitfailed", False, "AMSI bypass (amsiInitFailed)", Severity.HIGH, "evasion", "T1562.001"),
    ("etweventwrite", False, "ETW patching (telemetry blinding)", Severity.HIGH, "evasion", "T1562.006"),
    (r"-w(?:indowstyle)?\s+hidden", True, "Hidden window execution", Severity.MEDIUM, "evasion", "T1564.003"),
    (r"-nop(?:rofile)?\b", True, "PowerShell -NoProfile", Severity.LOW, "evasion", "T1059.001"),
    (r"-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass", True, "ExecutionPolicy Bypass", Severity.MEDIUM, "evasion", "T1059.001"),
    ("disablerealtimemonitoring", False, "Disables Defender real-time protection", Severity.HIGH, "evasion", "T1562.001"),
    ("set-mppreference", False, "Tampering with Defender preferences", Severity.HIGH, "evasion", "T1562.001"),
    ("add-mppreference", False, "Adds Defender exclusion", Severity.HIGH, "evasion", "T1562.001"),
    # --- persistence (T1547 / T1053) ---
    (r"currentversion\\?\\run", True, "Run-key persistence", Severity.HIGH, "persistence", "T1547.001"),
    ("schtasks", False, "Scheduled-task persistence (schtasks)", Severity.HIGH, "persistence", "T1053.005"),
    ("registerscheduledtask", False, "Scheduled-task persistence (PowerShell)", Severity.HIGH, "persistence", "T1053.005"),
    ("new-scheduledtask", False, "Scheduled-task persistence (PowerShell)", Severity.HIGH, "persistence", "T1053.005"),
    ("win32_startupcommand", False, "Startup-command persistence (WMI)", Severity.MEDIUM, "persistence", "T1547"),
    # --- process injection (T1055) ---
    ("virtualalloc", False, "VirtualAlloc (shellcode allocation)", Severity.HIGH, "injection", "T1055"),
    ("createremotethread", False, "CreateRemoteThread injection", Severity.HIGH, "injection", "T1055"),
    ("writeprocessmemory", False, "WriteProcessMemory injection", Severity.HIGH, "injection", "T1055"),
    ("ntmapviewofsection", False, "NtMapViewOfSection injection", Severity.HIGH, "injection", "T1055"),
    # --- credential access (T1003 / T1555) ---
    ("mimikatz", False, "Mimikatz reference (credential theft)", Severity.HIGH, "credential-access", "T1003"),
    ("sekurlsa", False, "sekurlsa (LSASS credential dump)", Severity.HIGH, "credential-access", "T1003.001"),
    ("convertto-securestring", False, "Hardcoded SecureString credential", Severity.LOW, "credential-access", "T1555"),
    # --- discovery (T1082 / T1057) ---
    ("get-wmiobject win32", False, "WMI host discovery", Severity.LOW, "discovery", "T1082"),
    (r"\bwhoami\b", True, "whoami discovery", Severity.LOW, "discovery", "T1033"),
    # --- anti-analysis (T1497) ---
    (r"vmware|virtualbox|\bvbox\b|qemu|sandbox", True, "VM/sandbox detection", Severity.MEDIUM, "anti-analysis", "T1497.001"),
    ("start-sleep", False, "Sleep delay (sandbox timeout evasion)", Severity.LOW, "anti-analysis", "T1497.003"),
]

# Short human label per category for the intent narrative.
_CAT_LABEL = {
    "download": "downloads a remote payload",
    "execution": "executes code dynamically",
    "evasion": "evades defenses (AMSI/ETW/Defender/hidden window)",
    "persistence": "establishes persistence",
    "injection": "injects into a process",
    "credential-access": "steals credentials",
    "discovery": "performs host discovery",
    "anti-analysis": "detects analysis environments",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class ScriptAnalyzer(Analyzer):
    name = "script"

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

        yield from self._obfuscation_metrics(text)

        # Build the deobfuscated view: PowerShell-specific decodes + the shared
        # JS/VBS deobfuscator. Behavioural matching runs over raw + recovered.
        recovered = self._powershell_decode(text)
        deob = DeobAnalyzer._script_deob(text.encode("latin1", "ignore"))
        if deob:
            recovered.append(deob.decode("latin1", "ignore"))
        haystack = "\n".join([text] + recovered).lower()
        full_text = "\n".join([text] + recovered)

        yield from self._behavioural(haystack, full_text)

    # ---- layer 1: obfuscation metrics ----------------------------------
    def _obfuscation_metrics(self, text: str) -> Iterable[Finding]:
        lowered = text.lower()
        if "#@~^" in text:
            yield Finding(
                analyzer=self.name,
                title="Encoded script (Microsoft Script Encoder VBE/JSE)",
                severity=Severity.HIGH, category="obfuscation",
                detail="Contains the #@~^ encoder marker; the real logic is hidden "
                       "behind reversible script encoding.")

        blobs = _B64_BLOB.findall(text)
        if blobs:
            longest = max(len(b) for b in blobs)
            yield Finding(
                analyzer=self.name,
                title=f"Embedded base64 blob ({longest} chars)",
                severity=Severity.MEDIUM if longest > 400 else Severity.LOW,
                category="obfuscation",
                detail="Large base64 strings commonly carry an encoded payload.")

        if _CHAR_ARRAY.search(text):
            yield Finding(
                analyzer=self.name, title="Character-code string construction",
                severity=Severity.MEDIUM, category="obfuscation",
                detail="Chr()/char-code concatenation hides literal strings.")

        if _HEX_ESCAPES.search(text):
            yield Finding(
                analyzer=self.name, title="Dense hex/percent escaping",
                severity=Severity.MEDIUM, category="obfuscation",
                detail="Long runs of \\xNN or %NN escapes obscure the real content.")

        if len(text) > 200:
            plus_ratio = text.count("+") / len(text)
            backtick_ratio = text.count("`") / len(text)
            if plus_ratio > 0.03 or backtick_ratio > 0.02:
                yield Finding(
                    analyzer=self.name,
                    title="High operator density (string-splitting obfuscation)",
                    severity=Severity.MEDIUM, category="obfuscation",
                    detail="Excessive '+'/backtick use is typical of obfuscated "
                           "PowerShell/JS.")

        if len(text) > 500 and text.count("\n") < 3 and _entropy(text) > 5.2:
            yield Finding(
                analyzer=self.name, title="Single-line high-entropy script",
                severity=Severity.MEDIUM, category="obfuscation",
                detail="Minified, high-entropy one-liner; typical of dropper stagers.")

        if len(text) > 20000:
            sample = text[:200_000]
            ws = sum(c.isspace() for c in sample) / len(sample)
            if ws < 0.05 and _entropy(sample) > 5.0:
                yield Finding(
                    analyzer=self.name,
                    title=f"Large obfuscated script ({len(text):,} chars, minimal "
                          "whitespace)",
                    severity=Severity.MEDIUM, category="obfuscation",
                    detail="Large high-entropy body with almost no whitespace; "
                           "typical of obfuscated/packed script droppers.")

    # ---- PowerShell-specific deobfuscation -----------------------------
    @staticmethod
    def _powershell_decode(text: str) -> list[str]:
        """Recover PowerShell payloads: -EncodedCommand (UTF-16LE base64),
        FromBase64String literals, and [char]-code join arrays."""
        out: list[str] = []
        for m in list(_PS_ENC.finditer(text))[:5] + list(_FROMB64.finditer(text))[:5]:
            blob = m.group(1)
            try:
                raw = base64.b64decode(blob + "===", validate=False)
            except (binascii.Error, ValueError):
                continue
            # PowerShell -enc is UTF-16LE; .NET payloads may be UTF-8.
            dec = raw[::2] if raw[1:2] == b"\x00" else raw
            txt = dec.decode("latin1", "ignore")
            if sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in txt[:256]) > len(txt[:256]) * 0.7:
                out.append(txt)
        # char-code join arrays -> string
        for m in list(_CHARJOIN.finditer(text))[:10]:
            nums = [int(n) for n in re.findall(r"\d{1,3}", m.group(1))]
            if len(nums) >= 6 and all(n < 256 for n in nums):
                s = "".join(chr(n) for n in nums)
                if sum(c.isprintable() for c in s) > len(s) * 0.8:
                    out.append(s)
        return out

    # ---- layer 2: behavioural intent -----------------------------------
    def _behavioural(self, haystack: str, full_text: str) -> Iterable[Finding]:
        fired: dict[str, list[str]] = {}
        seen: set[str] = set()
        for pat, is_re, title, sev, cat, attack in _INDICATORS:
            hit = re.search(pat, haystack) if is_re else (pat in haystack)
            if not hit or title in seen:
                continue
            seen.add(title)
            fired.setdefault(cat, []).append(attack)
            yield Finding(
                analyzer=self.name, title=title, severity=sev, category=cat,
                detail=f"Behaviour observed in script (ATT&CK {attack}).",
                data={"attack": attack})

        if not fired:
            return

        # Recover IOCs from the (deobfuscated) text so the analyst sees the
        # actual C2/payload, not just the behaviour class.
        urls = sorted(set(_URL_RE.findall(full_text)))[:15]
        ips = sorted({ip for ip in _IP_RE.findall(full_text)
                      if not ip.startswith(("10.", "127.", "192.168.", "0."))})[:15]

        # Intent narrative: chain the behaviour classes in kill-chain order.
        order = ["anti-analysis", "evasion", "download", "execution",
                 "injection", "persistence", "credential-access", "discovery"]
        chain = [_CAT_LABEL[c] for c in order if c in fired]
        attacks = sorted({a for ids in fired.values() for a in ids})
        sev = Severity.HIGH
        if {"download", "execution"} <= fired.keys() or "injection" in fired \
                or "persistence" in fired or "credential-access" in fired:
            sev = Severity.CRITICAL
        detail = "Script behaviour: " + "; then ".join(chain) + "."
        if urls or ips:
            detail += " | IOCs: " + ", ".join(urls + ips)
        yield Finding(
            analyzer=self.name,
            title="Malicious script behaviour chain",
            severity=sev, category="intel",
            detail=detail,
            data={"attack": attacks, "categories": sorted(fired),
                  "urls": urls, "ips": ips})
