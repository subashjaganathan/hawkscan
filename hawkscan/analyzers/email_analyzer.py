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
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".cab", ".ace", ".z", ".tar"}

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]{4,400}", re.I)
_HREF_RE = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                      re.I | re.S)
_IPHOST_RE = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}[:/]?", re.I)
_HOST_RE = re.compile(r"https?://([^/:?#\s]+)", re.I)
_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
               "cutt.ly", "rebrand.ly", "buff.ly", "rb.gy", "shorturl.at"}
_SUSPECT_TLDS = (".zip", ".mov", ".tk", ".top", ".xyz", ".gq", ".ml", ".cf",
                 ".ga", ".work", ".click", ".country", ".kim", ".loan")
_DOMAIN_TOKEN = re.compile(r"\b([a-z0-9-]+\.(?:com|net|org|io|co|ru|cn|gov|bank))\b",
                           re.I)


def _domain(addr: str) -> str:
    m = _DOMAIN_IN_ADDR.search(addr or "")
    return m.group(1).lower() if m else ""


def _host(url: str) -> str:
    m = _HOST_RE.match(url)
    return m.group(1).lower() if m else ""


def _reg_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


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

        # Display-name spoofing: the From display name claims a domain/brand that
        # differs from the actual sending address (e.g. "PayPal <x@gmail.com>").
        from_hdr = str(msg.get("From", ""))
        disp = from_hdr.split("<")[0]
        for dom in _DOMAIN_TOKEN.findall(disp):
            if from_d and _reg_domain(dom.lower()) != _reg_domain(from_d):
                yield Finding(
                    analyzer=self.name, title="Display-name domain spoofing",
                    severity=Severity.MEDIUM, category="spoofing",
                    detail=f"From display name cites '{dom}' but the address is "
                           f"@{from_d}.")
                break

        yield from self._analyze_body(msg, from_d)

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
            elif ext in _ARCHIVE_EXTS:
                yield Finding(
                    analyzer=self.name,
                    title=f"Archive attachment: {filename}",
                    severity=Severity.LOW, category="dropper",
                    detail="Archive attachments commonly wrap an executable payload "
                           "to evade mail filters.",
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

    def _analyze_body(self, msg, from_d: str) -> Iterable[Finding]:
        """URL/phishing analysis over the text and HTML body parts."""
        text = ""
        html = ""
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                body = part.get_payload(decode=True) or b""
                s = body.decode(part.get_content_charset() or "utf-8", "ignore")
            except Exception:
                continue
            if ctype == "text/html":
                html += s
            else:
                text += s

        # 1) Link display-text vs href mismatch (the core phishing trick).
        for href, anchor in _HREF_RE.findall(html):
            if not href.lower().startswith("http"):
                continue
            shown = re.sub(r"<[^>]+>", "", anchor)  # strip nested tags
            m = _DOMAIN_TOKEN.search(shown)
            if m:
                shown_dom = _reg_domain(m.group(1).lower())
                href_dom = _reg_domain(_host(href))
                if shown_dom and href_dom and shown_dom != href_dom:
                    yield Finding(
                        analyzer=self.name,
                        title="Hyperlink text/target mismatch (phishing)",
                        severity=Severity.HIGH, category="phishing",
                        detail=f"Link displays '{shown_dom}' but points to "
                               f"'{href_dom}'.",
                        data={"urls": [href]})
                    break

        # 2) Suspicious URLs across the whole body.
        urls = sorted(set(_URL_RE.findall(text + " " + html)))[:20]
        for u in urls:
            host = _host(u)
            if _IPHOST_RE.match(u):
                yield Finding(analyzer=self.name, title="Link to IP-literal host",
                              severity=Severity.MEDIUM, category="phishing",
                              detail=u[:160], data={"urls": [u]})
                break
        for u in urls:
            if "xn--" in _host(u):
                yield Finding(analyzer=self.name,
                              title="IDN/punycode URL (homograph risk)",
                              severity=Severity.MEDIUM, category="phishing",
                              detail=_host(u), data={"urls": [u]})
                break
        if any(_reg_domain(_host(u)) in _SHORTENERS for u in urls):
            yield Finding(analyzer=self.name, title="URL shortener link",
                          severity=Severity.LOW, category="phishing",
                          detail="Body contains a shortened URL hiding its target.")
        if any(_host(u).endswith(_SUSPECT_TLDS) for u in urls):
            yield Finding(analyzer=self.name, title="Link to suspicious TLD",
                          severity=Severity.LOW, category="phishing",
                          detail="Body links to a frequently-abused TLD.")
        if urls:
            yield Finding(analyzer=self.name, title=f"{len(urls)} URL(s) in email body",
                          severity=Severity.INFO, category="network",
                          detail="; ".join(urls[:6]), data={"urls": urls})
