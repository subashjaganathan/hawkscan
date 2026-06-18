"""PCAP network-capture analysis.

Parses classic libpcap files with the stdlib (struct) - no Scapy dependency -
and extracts network indicators useful for triage: contacted IPs, DNS queries,
HTTP Host headers, suspicious TLDs, DGA-like domains, and cleartext credentials.

PCAPNG is detected but not parsed (its block structure differs); the file is
still hashed/identified and scanned by the format-agnostic analyzers.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

_SUSPICIOUS_TLDS = (".ru", ".su", ".tk", ".top", ".xyz", ".gq", ".ml", ".cf",
                    ".ga", ".onion", ".bit", ".pw", ".cc", ".club", ".work")
_CRED_MARKERS = (b"Authorization: Basic", b"PASS ", b"USER ", b"password=",
                 b"pwd=", b"AUTH LOGIN")
_MAX_PACKETS = 200_000


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_dga(name: str) -> bool:
    # Long, high-entropy, mostly-consonant label = likely algorithmically generated.
    label = name.split(".")[0]
    if len(label) < 12:
        return False
    vowels = sum(c in "aeiou" for c in label.lower())
    return _entropy(label) > 3.6 and vowels / len(label) < 0.30


def _parse_dns_name(data: bytes, off: int) -> str:
    labels = []
    for _ in range(64):
        if off >= len(data):
            break
        ln = data[off]
        if ln == 0:
            break
        if ln & 0xC0:  # compression pointer - stop (good enough for queries)
            break
        labels.append(data[off + 1: off + 1 + ln].decode("latin1", "ignore"))
        off += 1 + ln
    return ".".join(labels)


class PcapAnalyzer(Analyzer):
    name = "pcap"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"pcap", "pcapng"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        if ctx.info.file_type == "pcapng":
            yield Finding(
                analyzer=self.name, title="PCAPNG capture (limited parsing)",
                severity=Severity.INFO, category="network",
                detail="PCAPNG block format is not fully parsed; convert to classic "
                       "pcap for full network-indicator extraction.")
            return

        endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        try:
            linktype = struct.unpack_from(endian + "I", data, 20)[0]
        except struct.error:
            return

        dst_ips: Counter = Counter()
        dns_names: set[str] = set()
        http_hosts: set[str] = set()
        times: dict[str, list[float]] = {}
        creds = False
        pkt_count = 0

        off = 24
        while off + 16 <= len(data) and pkt_count < _MAX_PACKETS:
            ts_sec, ts_usec, incl_len = struct.unpack_from(endian + "III", data, off)
            ts = ts_sec + ts_usec / 1_000_000
            off += 16
            pkt = data[off: off + incl_len]
            off += incl_len
            pkt_count += 1
            self._parse_packet(pkt, linktype, dst_ips, dns_names, http_hosts,
                               times, ts)
            if not creds and any(m in pkt for m in _CRED_MARKERS):
                creds = True

        yield Finding(
            analyzer=self.name,
            title=f"PCAP: {pkt_count} packets, {len(dst_ips)} unique destinations",
            severity=Severity.INFO, category="network",
            detail="; ".join(f"{ip}({n})" for ip, n in dst_ips.most_common(8)),
            data={"dst_ips": dict(dst_ips.most_common(50))},
        )

        if dns_names:
            yield Finding(
                analyzer=self.name, title=f"{len(dns_names)} DNS quer(y/ies)",
                severity=Severity.INFO, category="network",
                detail="; ".join(sorted(dns_names)[:12]),
                data={"dns": sorted(dns_names)[:200]})
        if http_hosts:
            yield Finding(
                analyzer=self.name, title=f"{len(http_hosts)} HTTP host(s)",
                severity=Severity.INFO, category="network",
                detail="; ".join(sorted(http_hosts)[:12]))

        sus = sorted({n for n in dns_names | http_hosts
                      if n.lower().endswith(_SUSPICIOUS_TLDS)})
        if sus:
            yield Finding(
                analyzer=self.name, title=f"{len(sus)} suspicious-TLD domain(s)",
                severity=Severity.MEDIUM, category="network",
                detail="; ".join(sus[:12]))

        # Beaconing: regular, low-jitter intervals to the same destination.
        for ip, stamps in times.items():
            if len(stamps) < 8:
                continue
            stamps.sort()
            intervals = [b - a for a, b in zip(stamps, stamps[1:]) if b - a > 0.05]
            if len(intervals) < 6:
                continue
            mean = sum(intervals) / len(intervals)
            if mean < 1:
                continue
            var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            cv = (var ** 0.5) / mean  # coefficient of variation; low = regular
            if cv < 0.15:
                yield Finding(
                    analyzer=self.name,
                    title=f"Beaconing to {ip} (~{mean:.0f}s interval)",
                    severity=Severity.HIGH, category="c2",
                    detail=f"{len(intervals)+1} connections at a near-constant "
                           f"interval (jitter {cv:.0%}); typical of C2 beaconing.")

        dga = sorted({n for n in dns_names if _looks_dga(n)})
        if dga:
            yield Finding(
                analyzer=self.name, title=f"{len(dga)} DGA-like domain(s)",
                severity=Severity.MEDIUM, category="c2",
                detail="; ".join(dga[:12]))

        if creds:
            yield Finding(
                analyzer=self.name, title="Cleartext credentials in traffic",
                severity=Severity.MEDIUM, category="credential-access",
                detail="HTTP Basic / FTP / form credentials transmitted in clear.")

    @staticmethod
    def _parse_packet(pkt, linktype, dst_ips, dns_names, http_hosts,
                      times=None, ts=0.0) -> None:
        # Locate the IPv4 header depending on link layer.
        if linktype == 1:  # Ethernet
            if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
                return
            ip_off = 14
        elif linktype in (101, 12):  # raw IP
            ip_off = 0
        else:
            return
        if len(pkt) < ip_off + 20 or (pkt[ip_off] >> 4) != 4:
            return

        ihl = (pkt[ip_off] & 0x0F) * 4
        proto = pkt[ip_off + 9]
        dst = ".".join(str(b) for b in pkt[ip_off + 16: ip_off + 20])
        dst_ips[dst] += 1
        if times is not None:
            times.setdefault(dst, []).append(ts)
        l4 = ip_off + ihl

        if proto == 6 and len(pkt) >= l4 + 20:  # TCP
            dport = struct.unpack_from(">H", pkt, l4 + 2)[0]
            doff = ((pkt[l4 + 12] >> 4) * 4)
            payload = pkt[l4 + doff:]
            if dport == 80 and b"Host:" in payload:
                for line in payload.split(b"\r\n"):
                    if line.lower().startswith(b"host:"):
                        http_hosts.add(line[5:].strip().decode("latin1", "ignore"))
        elif proto == 17 and len(pkt) >= l4 + 8:  # UDP
            dport = struct.unpack_from(">H", pkt, l4 + 2)[0]
            payload = pkt[l4 + 8:]
            if dport == 53 and len(payload) > 12:
                name = _parse_dns_name(payload, 12)
                if name:
                    dns_names.add(name)
