"""Capability + MITRE ATT&CK analysis.

Takes the API/function names a binary imports or references, groups them into
behavioural capability categories, and maps them to MITRE ATT&CK techniques.

API names come from (in order of preference):
  1. ctx.cache["api_names"] - the authoritative import table (set by PEAnalyzer).
  2. The extracted strings - a fallback for packed PEs, ELF and Mach-O binaries
     whose symbol/function names appear as strings.

The structured result is stashed in ctx.cache so the engine can attach it to
the ScanResult (for the report and JSON), and a finding is emitted per category
so capabilities also contribute to the verdict score.
"""

from __future__ import annotations

from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity
from ..intel import capabilities as cap_intel

_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


class CapabilityAnalyzer(Analyzer):
    name = "capability"

    def applies(self, ctx: AnalysisContext) -> bool:
        return ctx.info.file_type in {"pe", "elf", "macho"}

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        names = set(ctx.cache.get("api_names") or [])
        if not names:
            # Fallback: mine the extracted strings for known API/symbol names.
            blob = "\n".join(ctx.cache.get("strings") or [])
            names = cap_intel.scan_text(blob)
        if not names:
            return

        caps, techs = cap_intel.categorize(names)
        if not caps:
            return

        # Stash structured data for the engine/report/JSON.
        ctx.cache["capabilities"] = caps
        ctx.cache["mitre"] = techs

        # The per-category inventory is INFORMATIONAL (score 0). Individual API
        # presence is weak signal: legitimate software imports most of these.
        # It still appears in the report and JSON as a capability map.
        for category, cap in sorted(caps.items()):
            shown = ", ".join(cap.apis[:8])
            more = f" (+{len(cap.apis) - 8} more)" if len(cap.apis) > 8 else ""
            yield Finding(
                analyzer=self.name,
                title=f"Capability inventory: {category} ({len(cap.apis)} API"
                      f"{'s' if len(cap.apis) != 1 else ''})",
                severity=Severity.INFO,
                category="capability-inventory",
                detail=f"APIs: {shown}{more}.",
                data={"apis": cap.apis, "techniques": cap.techniques},
            )

        # High-confidence COMBINATIONS drive the score - these patterns are
        # rarely benign together (e.g. the process-injection triad).
        for hit in cap_intel.detect_combinations(names):
            tid, tname = hit["mitre"]
            yield Finding(
                analyzer=self.name,
                title=f"{hit['name']} ({', '.join(hit['apis'][:5])})",
                severity=_SEV.get(hit["severity"], Severity.MEDIUM),
                category=hit["category"],
                detail=f"{hit['detail']} ATT&CK: {tid} {tname}.",
                data={"apis": hit["apis"], "mitre": tid},
            )

        # Informational ATT&CK technique summary.
        if techs:
            ids = sorted(techs)
            yield Finding(
                analyzer=self.name,
                title=f"MITRE ATT&CK: {len(ids)} technique(s) referenced",
                severity=Severity.INFO,
                category="mitre",
                detail="; ".join(f"{tid} {techs[tid]['name']}" for tid in ids[:12]),
                data={"techniques": {tid: techs[tid] for tid in ids}},
            )
