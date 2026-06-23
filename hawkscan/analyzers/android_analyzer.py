"""Android APK / DEX static analysis.

Stdlib only. Rather than fully parsing the binary AndroidManifest (AXML) and the
DEX format, it extracts strings from AndroidManifest.xml and the DEX bytecode
(both keep their identifiers in string pools) and matches them against:

  - a permission database, categorized Dangerous / High-risk / Normal, and
  - a suspicious Android API / method database (SMS fraud, dynamic code loading,
    accessibility abuse, device-admin, IMEI/IMSI theft, command execution).

This gives a fast, dependency-free behavioural profile of an APK, similar in
spirit to the quick triage other tools provide.
"""

from __future__ import annotations

import zipfile
from typing import Iterable

from .base import Analyzer, AnalysisContext
from .strings_analyzer import extract_strings
from ..core.findings import Finding, Severity

# Permissions whose abuse is a strong malware signal.
_HIGH_RISK_PERMS = {
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS",
    "CALL_PHONE", "PROCESS_OUTGOING_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "REQUEST_INSTALL_PACKAGES", "REQUEST_DELETE_PACKAGES",
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "RECEIVE_BOOT_COMPLETED", "DISABLE_KEYGUARD", "READ_PHONE_STATE",
}
# Permissions that are sensitive but common.
_DANGEROUS_PERMS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "READ_CALENDAR", "BODY_SENSORS",
    "ACCESS_BACKGROUND_LOCATION", "QUERY_ALL_PACKAGES",
}

# (token, title, severity, category)
_SUSPICIOUS_METHODS: list[tuple[str, str, Severity, str]] = [
    ("sendTextMessage", "Sends SMS programmatically (toll fraud / OTP theft)", Severity.HIGH, "sms-fraud"),
    ("SmsManager", "Uses SmsManager", Severity.MEDIUM, "sms-fraud"),
    ("abortBroadcast", "Intercepts/suppresses broadcasts (SMS interception)", Severity.HIGH, "sms-intercept"),
    ("DexClassLoader", "Dynamic code loading (DexClassLoader)", Severity.HIGH, "dynamic-code"),
    ("PathClassLoader", "Dynamic code loading (PathClassLoader)", Severity.MEDIUM, "dynamic-code"),
    ("createPackageContext", "Loads code from another package", Severity.MEDIUM, "dynamic-code"),
    ("Runtime;->exec", "Executes shell commands (Runtime.exec)", Severity.HIGH, "execution"),
    ("ProcessBuilder", "Spawns processes (ProcessBuilder)", Severity.MEDIUM, "execution"),
    ("getDeviceId", "Reads IMEI (getDeviceId)", Severity.MEDIUM, "device-id"),
    ("getSubscriberId", "Reads IMSI (getSubscriberId)", Severity.MEDIUM, "device-id"),
    ("getSimSerialNumber", "Reads SIM serial", Severity.LOW, "device-id"),
    ("AccessibilityService", "Uses accessibility service (overlay/keylog abuse)", Severity.HIGH, "accessibility"),
    ("DevicePolicyManager", "Uses device-admin APIs", Severity.MEDIUM, "device-admin"),
    ("lockNow", "Can lock the device (ransomware)", Severity.MEDIUM, "device-admin"),
    ("resetPassword", "Can reset device password (ransomware)", Severity.HIGH, "device-admin"),
    ("getInstalledPackages", "Enumerates installed apps", Severity.LOW, "discovery"),
    ("TYPE_SYSTEM_ALERT", "Draws system overlay (phishing/clickjacking)", Severity.MEDIUM, "overlay"),
    ("/system/bin/su", "References su binary (root check)", Severity.MEDIUM, "root"),
    ("supersu", "References SuperSU (root)", Severity.LOW, "root"),
]


class AndroidAnalyzer(Analyzer):
    name = "android"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"apk", "dex"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        if ctx.info.file_type == "dex":
            findings = list(self._scan_dex(ctx.read_all()))
        else:
            # APK: pull the manifest and dex streams out of the zip.
            manifest = b""
            dex = bytearray()
            try:
                with zipfile.ZipFile(ctx.path) as zf:
                    names = zf.namelist()
                    if "AndroidManifest.xml" in names:
                        manifest = zf.read("AndroidManifest.xml")
                    for n in names:
                        if n.endswith(".dex"):
                            dex += zf.read(n)
            except Exception as exc:
                yield Finding(analyzer=self.name, title="Unreadable APK structure",
                              severity=Severity.LOW, category="format", detail=str(exc))
                return
            if not manifest and not dex:
                return
            findings.append(Finding(
                analyzer=self.name, title="Android application package",
                severity=Severity.INFO, category="format",
                detail=f"{len(names)} entries; "
                       f"{'manifest found' if manifest else 'no manifest'}."))
            if manifest:
                findings.extend(self._scan_permissions(manifest))
            if dex:
                findings.extend(self._scan_dex(bytes(dex)))

        yield from findings
        family = self._classify(findings)
        if family:
            yield family

    @staticmethod
    def _classify(findings: list[Finding]) -> Finding | None:
        """Heuristically classify the Android sample into a malware family type
        from the behaviour categories detected (original generic rules)."""
        cats = {f.category for f in findings}
        titles = " ".join(f.title.lower() for f in findings)
        family = None
        if "accessibility" in cats and ("overlay" in cats or "sms-intercept" in cats):
            family = "Banking trojan (overlay + accessibility abuse)"
        elif {"sms-fraud", "sms-intercept"} & cats and "device-id" in cats:
            family = "SMS trojan / OTP stealer"
        elif "device-admin" in cats and ("lock" in titles or "ransom" in titles
                                         or "resetpassword" in titles):
            family = "Android ransomware / locker"
        elif "dynamic-code" in cats and ("execution" in cats or "discovery" in cats):
            family = "RAT / dropper (dynamic code loading)"
        elif "accessibility" in cats or "device-id" in cats:
            family = "Spyware / stalkerware"
        if not family:
            return None
        return Finding(
            analyzer="android", title=f"Likely family: {family}",
            severity=Severity.HIGH, category="classification",
            detail="Heuristic classification from observed behaviours.")

    def _scan_permissions(self, manifest: bytes) -> Iterable[Finding]:
        strings, _ = extract_strings(manifest, min_len=6)
        perms = set()
        # Permissions may be separate string-pool entries (real AXML) or share a
        # string; split on whitespace so both cases resolve.
        for s in strings:
            for tok in s.split():
                if "permission." in tok:
                    perms.add(tok.rsplit(".", 1)[-1].strip(' "\'<>/'))

        high = sorted(perms & _HIGH_RISK_PERMS)
        dang = sorted(perms & _DANGEROUS_PERMS)
        if high:
            yield Finding(
                analyzer=self.name,
                title=f"High-risk permissions requested ({len(high)})",
                severity=Severity.HIGH if len(high) >= 2 else Severity.MEDIUM,
                category="permissions",
                detail=", ".join(high),
                data={"permissions": high},
            )
        if dang:
            yield Finding(
                analyzer=self.name,
                title=f"Dangerous permissions requested ({len(dang)})",
                severity=Severity.LOW,
                category="permissions",
                detail=", ".join(dang),
                data={"permissions": dang},
            )

    def _scan_dex(self, dex: bytes) -> Iterable[Finding]:
        strings, _ = extract_strings(dex, min_len=4)
        blob = "\n".join(strings)
        seen: set[str] = set()
        for token, title, sev, category in _SUSPICIOUS_METHODS:
            if token in blob and title not in seen:
                seen.add(title)
                yield Finding(
                    analyzer=self.name, title=title, severity=sev,
                    category=category, detail=f"DEX references {token!r}.",
                )
