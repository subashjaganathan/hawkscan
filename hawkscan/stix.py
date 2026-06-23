"""Export scan results as a STIX 2.1 bundle for threat-intel sharing.

Builds File + Indicator SDOs from the extracted IOCs (file hashes, URLs, IPs,
and any payload IOCs recovered by deobfuscation) so HawkScan output can be fed
into a TIP/SIEM. Stdlib only (json/uuid/datetime) - no stix2 dependency.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _collect_iocs(result) -> dict:
    urls, ips = set(), set()
    for f in result.findings:
        data = getattr(f, "data", {}) or {}
        urls.update(data.get("urls", []))
        urls.update(u for u in data.get("recovered_iocs", []) if u.startswith("http"))
        ips.update(data.get("ips", []))
    return {"urls": sorted(urls), "ips": sorted(ips)}


def build_bundle(results) -> dict:
    """Build a STIX 2.1 bundle dict from one or more ScanResult objects."""
    objects = []
    ts = _now()
    for r in results:
        info = r.info
        malicious = r.verdict.value >= 2  # Suspicious or worse
        labels = ["malicious-activity"] if malicious else ["benign"]

        file_obj = {
            "type": "file", "spec_version": "2.1", "id": _id("file"),
            "name": info.path.name,
            "hashes": {"MD5": info.md5, "SHA-1": info.sha1, "SHA-256": info.sha256},
        }
        objects.append(file_obj)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator"),
            "created": ts, "modified": ts,
            "name": f"HawkScan {r.verdict.label}: {info.path.name}",
            "description": f"HawkScan verdict {r.verdict.label} (score {r.score}).",
            "indicator_types": labels,
            "pattern": f"[file:hashes.'SHA-256' = '{info.sha256}']",
            "pattern_type": "stix", "valid_from": ts,
        })

        iocs = _collect_iocs(r)
        for url in iocs["urls"]:
            esc = url.replace("'", "\\'")
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": _id("indicator"),
                "created": ts, "modified": ts, "name": f"URL: {url[:60]}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{esc}']",
                "pattern_type": "stix", "valid_from": ts,
            })
        for ip in iocs["ips"]:
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": _id("indicator"),
                "created": ts, "modified": ts, "name": f"IP: {ip}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix", "valid_from": ts,
            })

    return {"type": "bundle", "id": _id("bundle"), "objects": objects}
