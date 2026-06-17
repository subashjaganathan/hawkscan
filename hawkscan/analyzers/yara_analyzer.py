"""YARA rule matching (optional, via yara-python).

Rules are loaded from the bundled rules/ directory or a path passed on the CLI.
A rule may set `meta.severity` (info|low|medium|high|critical) to control its
weight; otherwise matches default to HIGH.
"""

from __future__ import annotations

import hashlib
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
        # Gather every rule file across all directories (recursively, so a
        # whole rule TREE passed to --rules works) under unique namespaces.
        sources: dict[str, str] = {}
        for d in dirs:
            for rf in sorted(d.rglob("*.yar")) + sorted(d.rglob("*.yara")):
                ns = rf.stem
                while ns in sources:  # avoid namespace collisions across dirs
                    ns += "_"
                sources[ns] = str(rf)
        if not sources:
            return None

        # Fingerprint the rule set by path + size + mtime so the on-disk cache
        # is invalidated automatically whenever any rule file changes.
        fp = hashlib.sha256()
        for path in sorted(sources.values()):
            st = Path(path).stat()
            fp.update(f"{path}|{st.st_size}|{int(st.st_mtime)}".encode())
        key = fp.hexdigest()

        if key in _compiled_cache:
            return _compiled_cache[key]

        # On-disk compiled cache: turns the ~2s compile of a large ruleset into
        # a ~10ms load on every subsequent process invocation.
        cache_path = self._cache_path(key)
        if cache_path is not None and cache_path.exists():
            try:
                compiled = yara.load(str(cache_path))
                _compiled_cache[key] = compiled
                return compiled
            except yara.Error:
                cache_path.unlink(missing_ok=True)  # corrupt cache; recompile

        compiled = self._compile_sources(sources)
        if compiled is not None and cache_path is not None:
            try:
                compiled.save(str(cache_path))
            except yara.Error:
                pass  # caching is best-effort; never fail a scan over it
        _compiled_cache[key] = compiled
        return compiled

    @staticmethod
    def _compile_sources(sources: dict[str, str]):
        try:
            return yara.compile(filepaths=sources)
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
            return yara.compile(filepaths=good) if good else None

    @staticmethod
    def _cache_path(key: str) -> Path | None:
        from ..core.rules_update import USER_RULES_DIR

        cache_dir = USER_RULES_DIR.parent / "compiled"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        return cache_dir / f"{key}.yarac"

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
