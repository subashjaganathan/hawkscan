"""PCAP / PCAPNG network-capture analysis.

Parses classic libpcap and (basic) PCAPNG files with the stdlib (struct) - no
Scapy dependency - and extracts network indicators useful for triage: contacted
IPs, DNS queries, HTTP Host headers, TLS SNI server names (so HTTPS C2 is seen,
not just port-80 traffic), User-Agents and request URIs, suspicious TLDs,
DGA-like and DNS-tunnelling domains, C2 beaconing, and cleartext credentials.
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
# Request paths frequently used by commodity C2 panels / loaders.
_SUSPECT_URIS = ("/gate.php", "/panel", "/c2", "/bot", "/gate/", "/api/bot",
                 "/connect.php", "/submit.php", "/admin.php")
_MAX_PACKETS = 200_000


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_dga(name: str) -> bool:
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
        if ln & 0xC0:
            break
        labels.append(data[off + 1: off + 1 + ln].decode("latin1", "ignore"))
        off += 1 + ln
    return ".".join(labels)


def _tls_sni(payload: bytes) -> str:
    """Extract the SNI server_name from a TLS ClientHello, if present."""
    # record: 0x16 (handshake) 0x03 0xNN len(2); handshake: 0x01 (ClientHello)
    if len(payload) < 45 or payload[0] != 0x16 or payload[1] != 0x03:
        return ""
    try:
        p = 5
        if payload[p] != 0x01:  # ClientHello
            return ""
        p += 4                       # handshake type + length
        p += 2 + 32                  # client version + random
        sid_len = payload[p]; p += 1 + sid_len
        cs_len = struct.unpack_from(">H", payload, p)[0]; p += 2 + cs_len
        comp_len = payload[p]; p += 1 + comp_len
        if p + 2 > len(payload):
            return ""
        ext_total = struct.unpack_from(">H", payload, p)[0]; p += 2
        end = min(p + ext_total, len(payload))
        while p + 4 <= end:
            etype, elen = struct.unpack_from(">HH", payload, p); p += 4
            if etype == 0x0000:      # server_name extension
                # server_name_list(2) + type(1) + name_len(2) + name
                nlen = struct.unpack_from(">H", payload, p + 3)[0]
                return payload[p + 5:p + 5 + nlen].decode("latin1", "ignore")
            p += elen
    except (struct.error, IndexError):
        return ""
    return ""


class PcapAnalyzer(Analyzer):
    name = "pcap"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"pcap", "pcapng"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        acc = {
            "dst_ips": Counter(), "dns": set(), "http_hosts": set(),
            "sni": set(), "uas": set(), "uris": set(), "times": {}, "creds": False,
        }
        if ctx.info.file_type == "pcapng":
            pkt_count = self._iter_pcapng(data, acc)
        else:
            pkt_count = self._iter_pcap(data, acc)
        if pkt_count is None:
            return

        dst_ips = acc["dst_ips"]
        yield Finding(
            analyzer=self.name,
            title=f"PCAP: {pkt_count} packets, {len(dst_ips)} unique destinations",
            severity=Severity.INFO, category="network",
            detail="; ".join(f"{ip}({n})" for ip, n in dst_ips.most_common(8)),
            data={"dst_ips": dict(dst_ips.most_common(50))})

        if acc["dns"]:
            yield Finding(analyzer=self.name, title=f"{len(acc['dns'])} DNS quer(y/ies)",
                          severity=Severity.INFO, category="network",
                          detail="; ".join(sorted(acc["dns"])[:12]),
                          data={"dns": sorted(acc["dns"])[:200]})
        if acc["http_hosts"]:
            yield Finding(analyzer=self.name, title=f"{len(acc['http_hosts'])} HTTP host(s)",
                          severity=Severity.INFO, category="network",
                          detail="; ".join(sorted(acc["http_hosts"])[:12]))
        if acc["sni"]:
            yield Finding(analyzer=self.name,
                          title=f"{len(acc['sni'])} TLS SNI server name(s)",
                          severity=Severity.INFO, category="network",
                          detail="; ".join(sorted(acc["sni"])[:12]),
                          data={"sni": sorted(acc["sni"])[:200]})

        # Suspicious TLDs across all observed domains (DNS + HTTP + SNI).
        all_domains = acc["dns"] | acc["http_hosts"] | acc["sni"]
        sus = sorted({n for n in all_domains if n.lower().endswith(_SUSPICIOUS_TLDS)})
        if sus:
            yield Finding(analyzer=self.name, title=f"{len(sus)} suspicious-TLD domain(s)",
                          severity=Severity.MEDIUM, category="network",
                          detail="; ".join(sus[:12]))

        # Suspicious User-Agents (empty or non-browser) and C2-style URIs.
        odd_ua = sorted({u for u in acc["uas"]
                         if u and ("mozilla" not in u.lower() or len(u) < 20)})
        if odd_ua:
            yield Finding(analyzer=self.name, title="Non-browser/odd User-Agent(s)",
                          severity=Severity.MEDIUM, category="c2",
                          detail="; ".join(odd_ua[:6]))
        bad_uris = sorted({u for u in acc["uris"]
                           if any(s in u.lower() for s in _SUSPECT_URIS)})
        if bad_uris:
            yield Finding(analyzer=self.name, title="C2-style request URI(s)",
                          severity=Severity.MEDIUM, category="c2",
                          detail="; ".join(bad_uris[:8]))

        # Beaconing: regular, low-jitter intervals to the same destination.
        for ip, stamps in acc["times"].items():
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
            cv = (var ** 0.5) / mean
            if cv < 0.15:
                yield Finding(
                    analyzer=self.name,
                    title=f"Beaconing to {ip} (~{mean:.0f}s interval)",
                    severity=Severity.HIGH, category="c2",
                    detail=f"{len(intervals)+1} connections at a near-constant "
                           f"interval (jitter {cv:.0%}); typical of C2 beaconing.")

        dga = sorted({n for n in acc["dns"] if _looks_dga(n)})
        if dga:
            yield Finding(analyzer=self.name, title=f"{len(dga)} DGA-like domain(s)",
                          severity=Severity.MEDIUM, category="c2",
                          detail="; ".join(dga[:12]))

        # DNS tunnelling: many distinct long subdomains under one parent domain.
        parents: Counter = Counter()
        for n in acc["dns"]:
            parts = n.split(".")
            if len(parts) >= 3 and len(parts[0]) >= 20:
                parents[".".join(parts[-2:])] += 1
        tunnel = [d for d, c in parents.items() if c >= 6]
        if tunnel:
            yield Finding(analyzer=self.name, title="Possible DNS tunnelling",
                          severity=Severity.HIGH, category="c2",
                          detail="Many long unique subdomains under: "
                                 + ", ".join(tunnel[:4]))

        if acc["creds"]:
            yield Finding(analyzer=self.name, title="Cleartext credentials in traffic",
                          severity=Severity.MEDIUM, category="credential-access",
                          detail="HTTP Basic / FTP / form credentials transmitted in clear.")

    # ---- format iterators ----------------------------------------------
    def _iter_pcap(self, data, acc):
        endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        try:
            linktype = struct.unpack_from(endian + "I", data, 20)[0]
        except struct.error:
            return None
        off, n = 24, 0
        while off + 16 <= len(data) and n < _MAX_PACKETS:
            ts_sec, ts_usec, incl_len = struct.unpack_from(endian + "III", data, off)
            off += 16
            pkt = data[off: off + incl_len]
            off += incl_len
            n += 1
            self._parse_packet(pkt, linktype, acc, ts_sec + ts_usec / 1_000_000)
        return n

    def _iter_pcapng(self, data, acc):
        # Section Header Block sets byte order via the 0x1A2B3C4D magic.
        if data[:4] != b"\x0a\x0d\x0d\x0a":
            return None
        endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        linktype, off, n = 1, 0, 0
        while off + 8 <= len(data) and n < _MAX_PACKETS:
            try:
                btype, blen = struct.unpack_from(endian + "II", data, off)
            except struct.error:
                break
            if blen < 12 or off + blen > len(data):
                break
            body = data[off + 8: off + blen - 4]
            if btype == 0x00000001:                       # Interface Description
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
            elif btype == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
                cap_len = struct.unpack_from(endian + "I", body, 12)[0]
                pkt = body[20:20 + cap_len]
                n += 1
                self._parse_packet(pkt, linktype, acc, 0.0)
            elif btype == 0x00000003 and len(body) >= 4:    # Simple Packet Block
                pkt = body[4:]
                n += 1
                self._parse_packet(pkt, linktype, acc, 0.0)
            off += blen
        return n

    # ---- per-packet parsing --------------------------------------------
    @staticmethod
    def _parse_packet(pkt, linktype, acc, ts=0.0) -> None:
        if linktype == 1:  # Ethernet
            if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
                return
            ip_off = 14
        elif linktype in (101, 12, 14):  # raw IP
            ip_off = 0
        else:
            return
        if len(pkt) < ip_off + 20 or (pkt[ip_off] >> 4) != 4:
            return

        ihl = (pkt[ip_off] & 0x0F) * 4
        proto = pkt[ip_off + 9]
        dst = ".".join(str(b) for b in pkt[ip_off + 16: ip_off + 20])
        acc["dst_ips"][dst] += 1
        acc["times"].setdefault(dst, []).append(ts)
        l4 = ip_off + ihl

        if proto == 6 and len(pkt) >= l4 + 20:  # TCP
            dport = struct.unpack_from(">H", pkt, l4 + 2)[0]
            doff = ((pkt[l4 + 12] >> 4) * 4)
            payload = pkt[l4 + doff:]
            if not payload:
                return
            if not acc["creds"] and any(m in payload for m in _CRED_MARKERS):
                acc["creds"] = True
            if payload[:1] in (b"G", b"P", b"H") and b" HTTP/" in payload[:400]:
                lines = payload.split(b"\r\n")
                req = lines[0].split(b" ")
                if len(req) >= 2:
                    acc["uris"].add(req[1].decode("latin1", "ignore")[:200])
                for line in lines[1:]:
                    ll = line.lower()
                    if ll.startswith(b"host:"):
                        acc["http_hosts"].add(line[5:].strip().decode("latin1", "ignore"))
                    elif ll.startswith(b"user-agent:"):
                        acc["uas"].add(line[11:].strip().decode("latin1", "ignore")[:200])
            elif payload[:1] == b"\x16":  # TLS handshake -> ClientHello SNI
                sni = _tls_sni(payload)
                if sni:
                    acc["sni"].add(sni)
        elif proto == 17 and len(pkt) >= l4 + 8:  # UDP
            dport = struct.unpack_from(">H", pkt, l4 + 2)[0]
            payload = pkt[l4 + 8:]
            if dport == 53 and len(payload) > 12:
                name = _parse_dns_name(payload, 12)
                if name:
                    acc["dns"].add(name)
