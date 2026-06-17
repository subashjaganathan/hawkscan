"""YARA rule matching (optional, via yara-python).

Rules are loaded from the bundled rules/ directory or a path passed on the CLI.
A rule may set `meta.severity` (info|low|medium|high|critical) to control its
weight; otherwise matches default to HIGH.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import Analyzer, AnalysisContext
from ..core.findings import Finding, Severity

try:
    import yara  # type: ignore
    _HAVE_YARA = True
except Exception:
    _HAVE_YARA = False

_SEV_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}

_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_compiled_cache: dict = {}


def _collect_rule_dirs(custom: Path | None) -> list[Path]:
    """All directories to load rules from: built-in + downloaded + custom."""
    from ..core.rules_update import USER_RULES_DIR

    dirs = [_DEFAULT_RULES_DIR, USER_RULES_DIR]
    if custom:
        dirs.append(Path(custom))
    seen: list[Path] = []
    for d in dirs:
        if d.is_dir() and d not in seen:
            seen.append(d)
    return seen


class YaraAnalyzer(Analyzer):
    name = "yara"
    unavailable_reason = "yara-python not installed (pip install yara-python)"

    @classmethod
    def is_available(cls) -> bool:
        return _HAVE_YARA

    def applies(self, ctx: AnalysisContext) -> bool:
        return True

    @staticmethod
    def _severity_from_meta(meta: dict) -> Severity:
        # Explicit word severity wins (our built-in rules use this).
        if "severity" in meta:
            return _SEV_MAP.get(str(meta["severity"]).lower(), Severity.HIGH)
        # YARA-Forge & others use a numeric 0-100 score.
        for key in ("score", "threat_score", "rank"):
            if key in meta:
                try:
                    s = int(meta[key])
                except (TypeError, ValueError):
                    break
                if s >= 80:
                    return Severity.CRITICAL
                if s >= 60:
                    return Severity.HIGH
                if s >= 40:
                    return Severity.MEDIUM
                return Severity.LOW
        return Severity.HIGH

    def _compile(self, dirs: list[Path]):
        # Gather every rule file across all directories under unique namespaces.
        sources: dict[str, str] = {}
        for d in dirs:
            for rf in sorted(d.glob("*.yar")) + sorted(d.glob("*.yara")):
                ns = rf.stem
                while ns in sources:  # avoid namespace collisions across dirs
                    ns += "_"
                sources[ns] = str(rf)
        if not sources:
            return None

        key = "|".join(sorted(sources.values()))
        if key in _compiled_cache:
            return _compiled_cache[key]

        try:
            compiled = yara.compile(filepaths=sources)
        except yara.Error:
            # Community rulesets occasionally contain a file that won't compile
            # (missing module/external). Fall back to per-file so one bad file
            # doesn't disable the entire set.
            good: dict[str, str] = {}
            for ns, path in sources.items():
                try:
                    yara.compile(filepath=path)
                    good[ns] = path
                except yara.Error:
                    continue
            compiled = yara.compile(filepaths=good) if good else None
        _compiled_cache[key] = compiled
        return compiled

    def analyze(self, ctx: AnalysisContext) -> Iterable[Finding]:
        custom = ctx.cache.get("rules_dir")
        dirs = _collect_rule_dirs(Path(custom) if custom else None)
        if not dirs:
            return
        compiled = self._compile(dirs)
        if compiled is None:
            return

        matches = compiled.match(data=ctx.read_all())
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            sev = self._severity_from_meta(meta)
            desc = meta.get("description", "")
            yield Finding(
                analyzer=self.name,
                title=f"YARA rule match: {m.rule}",
                severity=sev,
                category=str(meta.get("category", "signature")),
                detail=desc or f"Matched YARA rule '{m.rule}'.",
                data={"tags": list(getattr(m, "tags", []))},
            )
