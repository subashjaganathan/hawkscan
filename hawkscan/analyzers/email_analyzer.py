"""Email (.eml / RFC 822) analysis.

Parses an email message with the stdlib email module and flags phishing and
malware-delivery indicators: authentication failures (SPF/DKIM/DMARC), sender
spoofing (From vs Return-Path/Reply-To), risky or double-extension attachments,
and attachments whose decoded bytes are actually executables.
"""

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_RISKY_ATTACH_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".ps1", ".jar", ".lnk", ".iso", ".img", ".msi",
    ".cpl", ".dll", ".one",
}
_DOUBLE_EXT = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|invoice)\.",
                         re.I)
_DOMAIN_IN_ADDR = re.compile(r"@([\w.-]+)")


def _domain(addr: str) -> str:
    m = _DOMAIN_IN_ADDR.search(addr or "")
    return m.group(1).lower() if m else ""


class EmailAnalyzer(Analyzer):
    name = "email"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type == "email"

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        try:
            msg = BytesParser(policy=policy.default).parsebytes(ctx.read_all())
        except Exception as exc:
            yield Finding(analyzer=self.name, title="Unparseable email",
                          severity=Severity.LOW, category="format", detail=str(exc))
            return

        subject = str(msg.get("Subject", ""))[:120]
        yield Finding(analyzer=self.name, title="Email message",
                      severity=Severity.INFO, category="format",
                      detail=f"Subject: {subject!r}" if subject else "")

        # Authentication results.
        auth = str(msg.get("Authentication-Results", "")).lower()
        recvspf = str(msg.get("Received-SPF", "")).lower()
        for token, label in (("spf=fail", "SPF"), ("dkim=fail", "DKIM"),
                             ("dmarc=fail", "DMARC")):
            if token in auth:
                yield Finding(
                    analyzer=self.name,
                    title=f"{label} authentication failed",
                    severity=Severity.MEDIUM, category="spoofing",
                    detail="Sender authentication failed; possible spoofing.",
                )
        if "fail" in recvspf and "spf=fail" not in auth:
            yield Finding(analyzer=self.name, title="Received-SPF: fail",
                          severity=Severity.MEDIUM, category="spoofing")

        # From vs Return-Path / Reply-To domain mismatch.
        from_d = _domain(str(msg.get("From", "")))
        rp_d = _domain(str(msg.get("Return-Path", "")))
        reply_d = _domain(str(msg.get("Reply-To", "")))
        if from_d and rp_d and from_d != rp_d:
            yield Finding(
                analyzer=self.name,
                title="From / Return-Path domain mismatch",
                severity=Severity.MEDIUM, category="spoofing",
                detail=f"From @{from_d} but Return-Path @{rp_d}.",
            )
        if from_d and reply_d and from_d != reply_d:
            yield Finding(
                analyzer=self.name,
                title="From / Reply-To domain mismatch",
                severity=Severity.LOW, category="spoofing",
                detail=f"From @{from_d} but Reply-To @{reply_d}.",
            )

        # Attachments.
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if not filename:
                continue
            low = filename.lower()
            ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""

            if _DOUBLE_EXT.search(low) and ext in _RISKY_ATTACH_EXTS:
                yield Finding(
                    analyzer=self.name,
                    title=f"Double-extension attachment: {filename}",
                    severity=Severity.HIGH, category="masquerading",
                    detail="Attachment disguises an executable as a document/image.",
                )
            elif ext in _RISKY_ATTACH_EXTS:
                yield Finding(
                    analyzer=self.name,
                    title=f"Risky attachment: {filename}",
                    severity=Severity.MEDIUM, category="dropper",
                    detail=f"Executable/script attachment ({ext}).",
                )

            # Decoded payload that begins with a known executable magic.
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            if payload[:2] == b"MZ" or payload[:4] == b"\x7fELF":
                yield Finding(
                    analyzer=self.name,
                    title=f"Attachment is an executable: {filename}",
                    severity=Severity.HIGH, category="dropper",
                    detail="Decoded attachment bytes start with an executable header.",
                )
