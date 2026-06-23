"""Extract printable strings and score suspicious indicators / IOCs.

This is format-agnostic: it works on any file and catches things deep parsers
miss (URLs in a data blob, base64 PowerShell in a document, etc.).
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# ASCII and UTF-16LE printable runs of length >= 4.
_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MUTEX_RE = re.compile(r"(?:Global|Local)\\[A-Za-z0-9_\-.{}]{4,40}")
_UA_RE = re.compile(r"Mozilla/[45]\.0[^\r\n\"'<>]{5,200}")
_PDB_RE = re.compile(r"[A-Za-z]:\\[^\s\"'<>|]{3,200}\.pdb", re.I)

# Benign domains that appear in legitimate binaries/documents (schemas, OS
# telemetry, certificate/OCSP endpoints, CDNs). URLs on these are filtered out
# of the IOC list so real C2 indicators stand out.
_WHITELIST_DOMAINS = (
    "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "schemas.xmlsoap.org", "microsoft.com", "windows.com", "windowsupdate.com",
    "msftncsi.com", "msftconnecttest.com", "digicert.com", "verisign.com",
    "symantec.com", "sectigo.com", "globalsign.com", "entrust.net",
    "ocsp.", "crl.", "go.microsoft.com", "apache.org", "python.org",
    "openssl.org", "gnu.org", "mozilla.org", "googleapis.com", "gstatic.com",
)


def _is_whitelisted(url: str) -> bool:
    low = url.lower()
    return any(d in low for d in _WHITELIST_DOMAINS)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

# (regex, title, severity, category) - high-signal capability strings.
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (re.compile(r"powershell.{0,40}-enc(?:odedcommand)?", re.I),
     "Encoded PowerShell command", Severity.HIGH, "execution"),
    (re.compile(r"-w(?:indowstyle)?\s+hidden", re.I),
     "Hidden window execution flag", Severity.MEDIUM, "execution"),
    (re.compile(r"\b(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|wget|curl)\b", re.I),
     "Network download primitive", Severity.MEDIUM, "network"),
    (re.compile(r"\bIEX\b|Invoke-Expression", re.I),
     "Dynamic code execution (IEX)", Severity.HIGH, "execution"),
    (re.compile(r"FromBase64String|base64.{0,10}decode", re.I),
     "Base64 decoding routine", Severity.LOW, "obfuscation"),
    # Note: raw injection/keylogging API *names* are handled by the capability
    # analyzer (with combination logic), not flagged here - a single API name as
    # a string is weak signal and false-positives on system DLLs that export it.
    (re.compile(r"\bcmd(?:\.exe)?\s*/c\b", re.I),
     "Command shell invocation", Severity.LOW, "execution"),
    (re.compile(r"schtasks|New-ScheduledTask|/Create\s+/SC", re.I),
     "Scheduled-task persistence", Severity.MEDIUM, "persistence"),
    (re.compile(r"CurrentVersion\\\\Run|HKCU\\\\.*Run|reg add.{0,40}Run", re.I),
     "Registry Run-key persistence", Severity.MEDIUM, "persistence"),
    (re.compile(r"vssadmin.{0,20}delete|wbadmin.{0,20}delete|bcdedit", re.I),
     "Shadow-copy / recovery tampering (ransomware)", Severity.HIGH, "ransomware"),
    (re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
     "Possible Bitcoin address", Severity.MEDIUM, "ransomware"),
    (re.compile(r"\.onion\b", re.I),
     "Tor hidden-service (.onion) reference", Severity.MEDIUM, "network"),
    (re.compile(r"\bkeylog(?:ger|ging)?\b", re.I),
     "Keylogging reference", Severity.MEDIUM, "spyware"),
]


def extract_strings(data: bytes, min_len: int = 4, limit: int = 200_000):
    """Return (strings, truncated). `truncated` is True if the limit was hit."""
    out: list[str] = []
    truncated = False
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("ascii", "ignore"))
        if len(out) >= limit:
            truncated = True
            break
    if not truncated:
        for m in _UTF16_RE.finditer(data):
            out.append(m.group().decode("utf-16le", "ignore"))
            if len(out) >= limit:
                truncated = True
                break
    return out, truncated


class StringsAnalyzer(Analyzer):
    name = "strings"

    def applies(self, ctx: AnalysisContext) -> bool:
        return True

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        strings, truncated = extract_strings(data)
        blob = "\n".join(strings)
        ctx.cache["strings"] = strings  # let other analyzers reuse

        if truncated:
            yield Finding(
                analyzer=self.name,
                title="String extraction truncated",
                severity=Severity.INFO,
                category="coverage",
                detail=f"Stopped after {len(strings):,} strings; indicators beyond "
                       "this point were not scanned.",
            )

        # Capability / behavior indicators.
        seen: set[str] = set()
        for pattern, title, severity, category in _SUSPICIOUS_PATTERNS:
            m = pattern.search(blob)
            if m and title not in seen:
                seen.add(title)
                sample = m.group()[:80]
                yield Finding(
                    analyzer=self.name,
                    title=title,
                    severity=severity,
                    category=category,
                    detail=f"Matched string: {sample!r}",
                )

        # Network IOCs (informational unless combined with other signals).
        all_urls = sorted(set(_URL_RE.findall(blob)))
        urls = [u for u in all_urls if not _is_whitelisted(u)][:25]
        filtered = len(all_urls) - len([u for u in all_urls if not _is_whitelisted(u)])
        ips = sorted({ip for ip in _IPV4_RE.findall(blob)
                      if not ip.startswith(("0.", "127.", "255."))})[:25]
        if urls:
            note = f" ({filtered} whitelisted hidden)" if filtered else ""
            yield Finding(
                analyzer=self.name,
                title=f"{len(urls)} embedded URL(s){note}",
                severity=Severity.INFO,
                category="network",
                detail="; ".join(urls[:10]),
                data={"urls": urls},
            )
        if ips:
            yield Finding(
                analyzer=self.name,
                title=f"{len(ips)} embedded IPv4 address(es)",
                severity=Severity.INFO,
                category="network",
                detail="; ".join(ips[:10]),
                data={"ips": ips},
            )

        # Additional IOCs (mutex/UA = behaviour, PDB path = attribution).
        mutexes = sorted(set(_MUTEX_RE.findall(blob)))[:15]
        if mutexes:
            yield Finding(analyzer=self.name, title=f"{len(mutexes)} mutex name(s)",
                          severity=Severity.INFO, category="ioc",
                          detail="; ".join(mutexes[:8]), data={"mutexes": mutexes})
        uas = sorted(set(_UA_RE.findall(blob)))[:10]
        if uas:
            yield Finding(analyzer=self.name, title=f"{len(uas)} User-Agent string(s)",
                          severity=Severity.INFO, category="ioc",
                          detail="; ".join(u[:60] for u in uas[:5]),
                          data={"user_agents": uas})
        pdbs = sorted(set(_PDB_RE.findall(blob)))[:5]
        if pdbs:
            yield Finding(analyzer=self.name, title="PDB path(s) present",
                          severity=Severity.INFO, category="attribution",
                          detail="; ".join(pdbs), data={"pdb_paths": pdbs})
