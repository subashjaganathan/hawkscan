"""Secrets and cloud-threat detection.

Format-agnostic: scans any file for leaked credentials and cloud-attack
indicators that matter for Windows/macOS/Linux/mobile/cloud incidents:
cloud access keys, private keys, API tokens, instance-metadata (IMDS) abuse,
and container/Kubernetes attack markers. These are high-signal because a real
credential or an IMDS-theft pattern is rarely benign in a delivered file.
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

# (regex, title, severity, category)
_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    # --- Cloud credentials ---
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}\b"),
     "AWS access key ID", Severity.HIGH, "secret"),
    (re.compile(r"aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+]{40}", re.I),
     "AWS secret access key", Severity.HIGH, "secret"),
    (re.compile(r'"type"\s*:\s*"service_account"'),
     "GCP service-account key (JSON)", Severity.HIGH, "secret"),
    (re.compile(r"DefaultEndpointsProtocol=.*AccountKey=[A-Za-z0-9+/=]{20,}", re.I),
     "Azure storage connection string", Severity.HIGH, "secret"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API key", Severity.MEDIUM, "secret"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"),
     "GitHub token", Severity.HIGH, "secret"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
     "Slack token", Severity.HIGH, "secret"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "Embedded private key", Severity.HIGH, "secret"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "JWT token", Severity.LOW, "secret"),

    # --- Cloud metadata / IMDS abuse (credential theft via SSRF) ---
    (re.compile(r"169\.254\.169\.254"),
     "Cloud instance-metadata (IMDS) endpoint", Severity.MEDIUM, "cloud"),
    (re.compile(r"metadata\.google\.internal|/computeMetadata/v1", re.I),
     "GCP metadata endpoint access", Severity.MEDIUM, "cloud"),
    (re.compile(r"/latest/meta-data/iam/security-credentials", re.I),
     "AWS IAM credential theft via IMDS", Severity.HIGH, "cloud"),

    # --- Container / Kubernetes attacks ---
    (re.compile(r"/var/run/docker\.sock"),
     "Docker socket access (container escape)", Severity.HIGH, "cloud"),
    (re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount"),
     "Kubernetes service-account token path", Severity.MEDIUM, "cloud"),
    (re.compile(r"kubectl\s+(?:get\s+secrets|--token)", re.I),
     "Kubernetes secret access", Severity.MEDIUM, "cloud"),
    (re.compile(r"\bnsenter\b.*--target\s+1|/proc/1/root", re.I),
     "Container escape via host namespace", Severity.HIGH, "cloud"),

    # --- Cloud CLI abuse / recon ---
    (re.compile(r"aws\s+sts\s+get-caller-identity|aws\s+iam\s+list", re.I),
     "AWS reconnaissance commands", Severity.LOW, "cloud"),
    (re.compile(r"aws\s+s3\s+(?:cp|sync)\s+.*s3://", re.I),
     "AWS S3 data transfer", Severity.LOW, "cloud"),
]


class SecretsAnalyzer(Analyzer):
    name = "secrets"

    def applies(self, ctx: AnalysisContext) -> bool:
        return True

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        # Search both raw bytes (as latin1 text) and extracted strings so this
        # works on scripts, configs and binaries alike.
        try:
            blob = ctx.read_all().decode("latin1", "ignore")
        except Exception:
            return
        cached = ctx.cache.get("strings")
        if cached:
            blob += "\n" + "\n".join(cached)

        seen: set[str] = set()
        for pattern, title, severity, category in _PATTERNS:
            m = pattern.search(blob)
            if m and title not in seen:
                seen.add(title)
                sample = m.group()[:60]
                yield Finding(analyzer=self.name, title=title, severity=severity,
                              category=category,
                              detail=f"Matched: {sample!r}")
