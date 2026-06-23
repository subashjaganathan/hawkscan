#!/usr/bin/env python3
"""Generate candidate YARA rule patterns from a sample, and emit a draft rule.

Embodies the rule-development workflow: extract high-signal strings, imports and
unique code byte-patterns, then print a ready-to-edit rule skeleton with proper
metadata, a filesize guard and a discriminating condition. Review and tighten the
output before adding it to a rule pack - this is an assistant, not an oracle.

    python tools/yara_assist.py <sample> [--name MyFamily_Variant]
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

# High-signal substrings worth anchoring a rule on (behaviour, not boilerplate).
_INTERESTING = ("http://", "https://", "cmd", "powershell", "mutex", "\\pipe\\",
                "schtasks", "CurrentVersion\\Run", "VirtualAlloc", "CreateRemote",
                "WriteProcessMemory", "WScript", "FromBase64", "Invoke-",
                ".onion", "/gate", "/api/", "bot", "stealer", "inject")
# Common library/boilerplate strings to avoid anchoring on.
_BORING = ("microsoft", "windows", "kernel32", "msvcrt", "gcc", "visual c++",
           "assembly", " 1.0", "copyright", "mscoree")


def _strings(data: bytes) -> list[str]:
    out = [m.group().decode("ascii", "ignore") for m in _ASCII.finditer(data)]
    out += [m.group().decode("utf-16le", "ignore") for m in _WIDE.finditer(data)]
    return out


def _candidate_strings(data: bytes, limit: int = 15) -> list[str]:
    seen, cands = set(), []
    for s in _strings(data):
        low = s.lower()
        if any(b in low for b in _BORING):
            continue
        if any(k.lower() in low for k in _INTERESTING) and s not in seen:
            seen.add(s)
            cands.append(s)
        if len(cands) >= limit:
            break
    return cands


def _unique_hex(data: bytes, n: int = 16, want: int = 4) -> list[str]:
    """Unique 16-byte sequences (low-null) as candidate code patterns."""
    freq: Counter = Counter()
    step = max(1, len(data) // 200_000)  # sample large files
    for i in range(0, len(data) - n, step * 4):
        chunk = data[i:i + n]
        if chunk.count(0) < n // 3:
            freq[chunk] += 1
    return [" ".join(f"{b:02X}" for b in c)
            for c, k in freq.items() if k == 1][:want]


def main() -> int:
    p = argparse.ArgumentParser(description="Draft a YARA rule from a sample.")
    p.add_argument("sample", type=Path)
    p.add_argument("--name", default="Suspicious_Family_VariantA")
    args = p.parse_args()

    from hawkscan.core import fileinfo
    data = args.sample.read_bytes()
    info = fileinfo.inspect(args.sample)
    is_pe = info.file_type == "pe"

    strs = _candidate_strings(data)
    hexes = _unique_hex(data) if is_pe else []

    lines = [f"rule {args.name}", "{", "    meta:",
             '        description = "REVIEW: detects ' + args.name + '"',
             '        author = "dfir-hawk"',
             '        date = "REVIEW"',
             f'        hash = "{info.sha256}"',
             '        tlp = "WHITE"', "    strings:"]
    for i, s in enumerate(strs):
        esc = s.replace("\\", "\\\\").replace('"', '\\"')[:80]
        lines.append(f'        $s{i} = "{esc}" ascii wide')
    for i, h in enumerate(hexes):
        lines.append(f"        $h{i} = {{ {h} }}")
    lines.append("    condition:")
    guard = "uint16(0) == 0x5A4D and " if is_pe else ""
    parts = []
    if strs:
        parts.append(f"{min(2, len(strs))} of ($s*)")
    if hexes:
        parts.append("any of ($h*)")
    cond = " and ".join(parts) or "any of them"
    lines.append(f"        {guard}filesize < 10MB and ({cond})")
    lines.append("}")

    print(f"// candidates from {args.sample.name} "
          f"({len(strs)} strings, {len(hexes)} hex)\n")
    print("\n".join(lines))
    print("\n// Tighten before shipping: keep only family-unique strings, verify "
          "against a clean corpus (target <0.1% FP).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
