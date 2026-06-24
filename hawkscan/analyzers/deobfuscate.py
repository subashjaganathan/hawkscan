"""Unpacking / deobfuscation layer.

Recovers a hidden second stage and re-scans it, so a benign-looking wrapper
whose real payload is packed or encoded still gets caught. Handles:

  * UPX-packed PEs  -> unpack with the `upx` tool (if installed) and re-scan.
  * Scripts/text    -> decode large base64 (and hex) blobs and re-scan the result.

Recovered payloads are scanned with a deob-free engine (so it can't recurse
forever), and a finding summarises what the hidden stage turned out to be.
"""

from __future__ import annotations

import base64
import binascii
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity, Verdict

_B64 = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
_HEX = re.compile(rb"(?:[0-9A-Fa-f]{2}){40,}")
_MAX_PAYLOADS = 3
_XOR_MAX_SIZE = 16 * 1024 * 1024  # cap XOR brute to bound cost

# High-confidence plaintext markers to brute single-byte XOR against. A match on
# any of these for key K>0 means the carrier hides XOR-encoded content.
_XOR_MARKERS: list[tuple[bytes, str]] = [
    (b"This program cannot be run in DOS mode", "PE"),
    (b"powershell", "script"),
    (b"cmd.exe /c", "script"),
    (b"CreateProcess", "api"),
    (b"http://", "url"),
    (b"InvokeExpression", "script"),
]
_VERDICT_SEV = {
    Verdict.MALICIOUS: Severity.CRITICAL,
    Verdict.LIKELY_MALICIOUS: Severity.HIGH,
    Verdict.SUSPICIOUS: Severity.MEDIUM,
}


class DeobAnalyzer(Analyzer):
    name = "deobfuscate"

    def applies(self, ctx: AnalysisContext) -> bool:
        if ctx.cache.get("_no_deob"):
            return False  # we are already inside a recovered-payload scan
        return ctx.info.file_type in {"pe", "script", "text", "data"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        data = ctx.read_all()
        recovered: list[tuple[str, bytes]] = []

        if ctx.info.file_type == "pe":
            up = self._upx_unpack(ctx)
            if up:
                recovered.append(("UPX unpack", up))

        if ctx.info.file_type in {"script", "text"}:
            # Unroll JS/script obfuscation (fromCharCode / \x / \u / unescape /
            # string concat) to reveal hidden URLs and commands.
            deob = self._script_deob(data)
            if deob and deob != data and self._meaningful(deob):
                recovered.append(("script deobfuscation", deob))
            blobs = self._decode_blobs(data)
            recovered.extend(blobs)
            # Multi-layer: a decoded blob may itself be XOR-encoded.
            for _, dec in blobs[:_MAX_PAYLOADS]:
                recovered.extend(self._xor_recover(dec, layer="base64+"))

        # Single-byte XOR recovery on the raw file (catches XOR-encoded payloads
        # in any binary/data carrier, e.g. a dropper hiding an XOR'd PE).
        recovered.extend(self._xor_recover(data))

        seen: set[bytes] = set()
        for label, payload in recovered[:_MAX_PAYLOADS]:
            key = payload[:64]
            if key in seen:
                continue
            seen.add(key)
            yield from self._rescan(label, payload)

    # ---- recovery -------------------------------------------------------
    def _upx_unpack(self, ctx: AnalysisContext) -> bytes | None:
        data = ctx.read_all()
        if b"UPX!" not in data[:4096] and b"UPX0" not in data:
            return None
        if not shutil.which("upx"):
            return None
        tmp = Path(tempfile.mkdtemp(prefix="hawkscan_upx_"))
        try:
            src = tmp / "in.bin"
            out = tmp / "out.bin"
            src.write_bytes(data)
            r = subprocess.run(["upx", "-d", "-o", str(out), str(src)],
                               capture_output=True, timeout=60)
            if r.returncode == 0 and out.exists():
                return out.read_bytes()
        except Exception:
            return None
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return None

    def _decode_blobs(self, data: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        for m in _B64.finditer(data):
            try:
                dec = base64.b64decode(m.group() + b"===", validate=False)
            except (binascii.Error, ValueError):
                continue
            if self._meaningful(dec):
                out.append(("base64 decode", dec))
            # UTF-16LE PowerShell payloads decode with interleaved nulls.
            if dec[1:2] == b"\x00":
                stripped = dec[::2]
                if self._meaningful(stripped):
                    out.append(("base64+UTF-16 decode", stripped))
            if len(out) >= _MAX_PAYLOADS:
                return out
        for m in _HEX.finditer(data):
            try:
                dec = bytes.fromhex(m.group().decode("ascii"))
            except ValueError:
                continue
            if self._meaningful(dec):
                out.append(("hex decode", dec))
            if len(out) >= _MAX_PAYLOADS:
                break
        return out

    @staticmethod
    def _script_deob(data: bytes, max_size: int = 8 * 1024 * 1024) -> bytes:
        """Unroll common JS/script obfuscation to reveal the underlying content.

        Handles, gated on a trigger so normal text is never mangled:
          * eval(function(p,a,c,k,e,d){...}) Dean-Edwards / packer output,
          * obfuscator.io string-array indirection (non-rotated),
          * String.fromCharCode(...) including hex args and integer arithmetic,
          * \\xNN / \\uNNNN escapes, unescape('%NN'),
          * adjacent string concatenation ("a"+"b"),
          * a single eval('literal') / eval("literal") wrapper layer.
        Iterated several times so layered schemes peel one ring per pass."""
        if not (32 <= len(data) <= max_size):
            return b""
        try:
            text = data.decode("latin1", "ignore")
        except Exception:
            return b""

        def _fcc(m):
            # Evaluate each comma-separated arg as a safe integer expression so
            # decimal, 0x-hex and arithmetic (0x68+0, 104-0) all resolve.
            out = []
            for part in m.group(1).split(","):
                p = part.strip()
                if not p:
                    continue
                if not re.fullmatch(r"[0-9a-fA-FxX+\-* ()]+", p):
                    return m.group(0)  # unexpected token: leave untouched
                try:
                    v = int(eval(p, {"__builtins__": {}}, {}))  # whitelisted chars only
                except Exception:
                    return m.group(0)
                if 0 <= v < 0x110000:
                    out.append(chr(v))
            s = "".join(out)
            # Re-quote (when safe) so adjacent concat reassembles a full literal.
            return f'"{s}"' if '"' not in s and "\n" not in s else s

        for _ in range(6):
            before = text
            low = text.lower()
            if "eval(function(p,a,c,k,e,d)" in text.replace(" ", ""):
                text = DeobAnalyzer._eval_packer(text)
            if "fromcharcode" in low:
                text = re.sub(
                    r"(?:String\.)?fromCharCode\(([0-9a-fA-FxX,\s+\-*()]+)\)",
                    _fcc, text)
            text = re.sub(r"\\x([0-9a-fA-F]{2})",
                          lambda m: chr(int(m.group(1), 16)), text)
            text = re.sub(r"\\u([0-9a-fA-F]{4})",
                          lambda m: chr(int(m.group(1), 16)), text)
            if "unescape" in low or "decodeuri" in low:
                text = re.sub(r"%([0-9a-fA-F]{2})",
                              lambda m: chr(int(m.group(1), 16)), text)
            text = re.sub(r"""["']\s*\+\s*["']""", "", text)  # "a"+"b" -> "ab"
            text = DeobAnalyzer._string_array(text)
            # Peel a single eval('...') / eval("...") wrapper so the next pass
            # sees the inner stage. Only when the argument is one string literal.
            mev = re.search(r"\beval\(\s*(['\"])((?:\\.|(?!\1).)*)\1\s*\)", text)
            if mev:
                inner = DeobAnalyzer._js_unescape(mev.group(2))
                if len(inner) >= 8:
                    text = text[:mev.start()] + inner + text[mev.end():]
            if text == before:
                break
        return text.encode("latin1", "ignore")

    @staticmethod
    def _js_unescape(s: str) -> str:
        """Decode the common JS single/double-quoted string escapes."""
        return (s.replace("\\\\", "\\").replace("\\'", "'").replace('\\"', '"')
                 .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
                 .replace("\\/", "/"))

    @staticmethod
    def _eval_packer(text: str) -> str:
        """Unroll Dean-Edwards `eval(function(p,a,c,k,e,d){...}(p,a,c,k,...))`
        packer output (radix <= 36). Bails (returns text unchanged) on any shape
        it does not understand, so it can never corrupt a non-packer script."""
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"

        def enc(n: int, base: int) -> str:
            if n == 0:
                return "0"
            s = ""
            while n > 0:
                s = digits[n % base] + s
                n //= base
            return s

        pat = re.compile(
            r"\}\s*\(\s*(['\"])(?P<p>(?:\\.|(?!\1).)*)\1\s*,\s*"
            r"(?P<a>\d+)\s*,\s*(?P<c>\d+)\s*,\s*"
            r"(['\"])(?P<k>(?:\\.|(?!\4).)*)\4\.split\(\s*(['\"])\|\6\s*\)",
            re.S)
        out = text
        for m in pat.finditer(text):
            try:
                a = int(m.group("a"))
                c = int(m.group("c"))
                if a > 36 or c > 100000:
                    continue
                p = DeobAnalyzer._js_unescape(m.group("p"))
                k = DeobAnalyzer._js_unescape(m.group("k")).split("|")
                for i in range(c - 1, -1, -1):
                    tok = k[i] if i < len(k) and k[i] else enc(i, a)
                    p = re.sub(r"\b" + re.escape(enc(i, a)) + r"\b",
                               lambda _m, t=tok: t, p)
                out = out.replace(m.group(0), "}('__unpacked__'));" + p, 1)
            except Exception:
                continue
        return out

    @staticmethod
    def _string_array(text: str) -> str:
        """Resolve obfuscator.io string-array indirection for the common,
        non-rotated shape: a `var NAME=['s',...]` literal plus a getter
        `function GET(i,k){i=i-OFF;return NAME[i];}`, with calls `GET(0xNN)`.
        Bails if a rotation IIFE (push/shift reorder) is present, since the
        static index->string mapping would then be wrong."""
        ma = re.search(r"var\s+(_0x[0-9a-f]+)\s*=\s*\[([^\]]*)\]\s*;", text)
        if not ma:
            return text
        name = ma.group(1)
        # Rotation present -> static decode unsafe.
        if re.search(r"\[['\"]push['\"]\]|\[['\"]shift['\"]\]|\.push\(\w+\.shift",
                     text):
            return text
        items = re.findall(r"(['\"])((?:\\.|(?!\1).)*)\1", ma.group(2))
        arr = [DeobAnalyzer._js_unescape(v) for _, v in items]
        if not arr:
            return text
        # Find the getter: a function whose (brace-flat) body returns NAME[...].
        getter = None
        off = 0
        for mg in re.finditer(
                r"function\s+(_0x[0-9a-f]+)\s*\([^)]*\)\s*\{([^{}]*)\}", text):
            body = mg.group(2)
            if name + "[" not in body.replace(" ", ""):
                continue
            getter = mg.group(1)
            # Offset may be inline (NAME[i-OFF]) or on its own line (i=i-OFF).
            mo = re.search(r"-\s*(0x[0-9a-fA-F]+|\d+)", body)
            if mo:
                off = int(mo.group(1), 16) if mo.group(1).lower().startswith("0x") \
                    else int(mo.group(1))
            break
        if getter is None:
            return text

        def _sub(m):
            idx = int(m.group(1), 16) if m.group(1).lower().startswith("0x") \
                else int(m.group(1))
            j = idx - off
            if 0 <= j < len(arr):
                s = arr[j]
                if '"' not in s and "\n" not in s:
                    return f'"{s}"'
            return m.group(0)

        return re.sub(re.escape(getter) + r"\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                      _sub, text)

    @staticmethod
    def _xor_recover(data: bytes, layer: str = "") -> list[tuple[str, bytes]]:
        """Brute single-byte XOR keys (1-255). If a known plaintext marker
        appears XOR'd with key K, decode the whole buffer with K and return it.
        Cheap: only small marker searches run until a hit; full XOR happens once.
        """
        if not (64 <= len(data) <= _XOR_MAX_SIZE):
            return []
        for k in range(1, 256):
            for marker, kind in _XOR_MARKERS:
                if bytes(c ^ k for c in marker) in data:
                    dec = bytes(b ^ k for b in data)
                    if kind == "PE":
                        mz = dec.find(b"MZ")
                        dec = dec[mz:] if mz != -1 else dec
                    return [(f"{layer}single-byte XOR 0x{k:02x}", dec)]
        return []

    @staticmethod
    def _meaningful(dec: bytes) -> bool:
        if len(dec) < 16:
            return False
        if dec[:2] == b"MZ" or dec[:4] == b"\x7fELF":
            return True
        printable = sum(1 for b in dec[:512] if 9 <= b <= 13 or 32 <= b <= 126)
        return printable / min(len(dec), 512) > 0.80

    # ---- re-scan --------------------------------------------------------
    def _rescan(self, label: str, data: bytes) -> Iterable[Finding]:
        from ..core.engine import Engine
        from ..analyzers import ALL_ANALYZERS

        # Excluding DeobAnalyzer from the sub-engine prevents infinite recursion.
        sub = Engine(analyzers=[c for c in ALL_ANALYZERS if c is not DeobAnalyzer])
        # In-memory re-scan: the recovered (often malicious) payload is never
        # written to disk, so it cannot be quarantined by an on-access EDR.
        try:
            res = sub.scan_bytes(data, name="payload.bin")
        except Exception as exc:
            yield Finding(analyzer=self.name,
                          title=f"Recovered hidden payload ({label})",
                          severity=Severity.LOW, category="deobfuscation",
                          detail=f"Could not re-scan recovered stage: {exc}")
            return

        sev = _VERDICT_SEV.get(res.verdict, Severity.INFO)
        top = [f.title for f in res.findings if f.severity >= Severity.MEDIUM][:4]
        # Pull the concrete IOCs recovered from the hidden stage (URLs/IPs) so
        # the analyst sees the actual C2/payload, not just "it's malicious".
        iocs: list[str] = []
        for f in res.findings:
            iocs.extend(f.data.get("urls", []))
            iocs.extend(f.data.get("ips", []))
        iocs = sorted(set(iocs))[:10]
        detail = ("Recovered stage findings: " + "; ".join(top)) if top \
            else f"Recovered a {len(data):,}-byte hidden stage."
        if iocs:
            detail += " | IOCs: " + ", ".join(iocs)
        yield Finding(
            analyzer=self.name,
            title=f"Hidden payload via {label}: {res.verdict.label}",
            severity=sev,
            category="deobfuscation",
            detail=detail,
            data={"recovered_verdict": res.verdict.label,
                  "recovered_size": len(data), "recovered_iocs": iocs},
        )
