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
        return ctx.info.file_type in {"pe", "script", "text"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        recovered: list[tuple[str, bytes]] = []

        if ctx.info.file_type == "pe":
            up = self._upx_unpack(ctx)
            if up:
                recovered.append(("UPX unpack", up))

        if ctx.info.file_type in {"script", "text"}:
            recovered.extend(self._decode_blobs(ctx.read_all()))

        for label, data in recovered[:_MAX_PAYLOADS]:
            yield from self._rescan(label, data)

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
        tmp = Path(tempfile.mkdtemp(prefix="hawkscan_deob_"))
        try:
            f = tmp / "payload.bin"
            f.write_bytes(data)
            res = sub.scan(f)
        except Exception as exc:
            yield Finding(analyzer=self.name,
                          title=f"Recovered hidden payload ({label})",
                          severity=Severity.LOW, category="deobfuscation",
                          detail=f"Could not re-scan recovered stage: {exc}")
            return
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        sev = _VERDICT_SEV.get(res.verdict, Severity.INFO)
        top = [f.title for f in res.findings if f.severity >= Severity.MEDIUM][:4]
        yield Finding(
            analyzer=self.name,
            title=f"Hidden payload via {label}: {res.verdict.label}",
            severity=sev,
            category="deobfuscation",
            detail=("Recovered stage findings: " + "; ".join(top)) if top
                   else f"Recovered a {len(data):,}-byte hidden stage.",
            data={"recovered_verdict": res.verdict.label,
                  "recovered_size": len(data)},
        )
