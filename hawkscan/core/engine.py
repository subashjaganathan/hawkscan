"""Scan orchestration: run analyzers, aggregate findings into a verdict."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import fileinfo
from .findings import Finding, Severity, Verdict, score_to_verdict


@dataclass
class ScanResult:
    info: fileinfo.FileInfo
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: Verdict = Verdict.CLEAN
    analyzers_run: list[str] = field(default_factory=list)
    analyzers_skipped: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    traces: dict[str, str] = field(default_factory=dict)  # full tracebacks (debug)
    raw_score: int = 0  # pre-cap score, for transparency
    capabilities: dict[str, Any] = field(default_factory=dict)  # category -> {apis, techniques}
    mitre: dict[str, Any] = field(default_factory=dict)         # technique id -> {name, ...}
    dynamic: dict[str, Any] = field(default_factory=dict)        # behavioural-analysis result
    virustotal: dict[str, Any] = field(default_factory=dict)     # optional VT enrichment
    duration_ms: float = 0.0

    @property
    def confidence(self) -> str:
        """Rough confidence in the verdict from the strength of evidence."""
        if any(f.severity >= Severity.CRITICAL for f in self.findings):
            return "high"
        highs = sum(1 for f in self.findings if f.severity >= Severity.HIGH)
        if highs >= 2:
            return "high"
        if highs == 1 or self.score >= 45:
            return "medium"
        return "low"

    def to_dict(self, include_traces: bool = False) -> dict[str, Any]:
        d = {
            "file": {
                "path": str(self.info.path),
                "size": self.info.size,
                "type": self.info.file_type,
                "description": self.info.description,
                "extension": self.info.extension,
                "magic": self.info.magic_hex,
                "ext_mismatch": self.info.ext_mismatch,
                "md5": self.info.md5,
                "sha1": self.info.sha1,
                "sha256": self.info.sha256,
            },
            "verdict": self.verdict.label,
            "score": self.score,
            "raw_score": self.raw_score,
            "confidence": self.confidence,
            "capabilities": self.capabilities,
            "mitre_attack": self.mitre,
            "dynamic": self.dynamic,
            "virustotal": self.virustotal,
            "findings": [f.to_dict() for f in self.findings],
            "analyzers_run": self.analyzers_run,
            "analyzers_skipped": self.analyzers_skipped,
            "errors": self.errors,
            "duration_ms": round(self.duration_ms, 1),
        }
        if include_traces and self.traces:
            d["traces"] = self.traces
        return d


# Files larger than this are hashed/identified but skip the deep (full-read)
# analyzers, to bound memory and time. Override via Engine(max_scan_size=...).
DEFAULT_MAX_SCAN_SIZE = 256 * 1024 * 1024  # 256 MiB

# No single category may contribute more than this to the score. Stops a broad
# ruleset matching many rules of one theme from trivially maxing the verdict.
# Overridable via hawkscan.toml ([scoring] category_cap).
from . import config as _config  # noqa: E402
CATEGORY_SCORE_CAP = _config.category_cap()

# Non-executable document/data formats. Keyword/IOC matches in these are usually
# descriptive (docs, detection rules, logs), so a heuristic-only verdict on them
# is capped. A YARA or CRITICAL hit still escalates (e.g. a ransom note).
_INERT_DOC_EXTS = {
    ".md", ".rst", ".txt", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".tex", ".rtfd",
}

# Per-user hash lists (SHA-256, one per line, '#' comments). The allowlist marks
# known-good files (forced Clean); the denylist marks known-bad files (forced
# Malicious) for instant offline detection of samples you have already triaged.
_ALLOWLIST_PATH = Path.home() / ".hawkscan" / "allowlist.txt"
_DENYLIST_PATH = Path.home() / ".hawkscan" / "denylist.txt"
# Labelled hash database: "sha256[ <label>]" per line. A non-"clean" label
# forces a Malicious verdict; the label (e.g. family name) is shown.
_HASHDB_PATH = Path.home() / ".hawkscan" / "hashdb.txt"


def _load_hashdb(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for ln in lines:
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        parts = ln.split(None, 1)
        h = parts[0].lower()
        if len(h) == 64:
            out[h] = parts[1].strip() if len(parts) > 1 else "malicious"
    return out


def _load_hashlist(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    out = set()
    for ln in lines:
        ln = ln.split("#", 1)[0].strip().lower()
        if len(ln) == 64:
            out.add(ln)
    return out


def _load_allowlist() -> set[str]:
    return _load_hashlist(_ALLOWLIST_PATH)


class Engine:
    def __init__(self, analyzers: list | None = None, rules_dir: Path | None = None,
                 max_scan_size: int = DEFAULT_MAX_SCAN_SIZE,
                 extract_dir: Path | None = None):
        # Imported here to avoid a circular import at module load.
        from ..analyzers import ALL_ANALYZERS

        self.analyzer_classes = analyzers if analyzers is not None else ALL_ANALYZERS
        self.rules_dir = rules_dir
        self.max_scan_size = max_scan_size
        self.extract_dir = extract_dir
        self.allowlist = _load_allowlist()
        self.denylist = _load_hashlist(_DENYLIST_PATH)
        self.hashdb = _load_hashdb(_HASHDB_PATH)

    def scan_bytes(self, data: bytes, name: str = "payload.bin") -> ScanResult:
        """Scan in-memory bytes without writing them to disk. Used for nested
        re-scans (deobfuscated stages, archive members) so recovered payloads
        never land on the filesystem and trip an EDR. Path-based deep parsers
        (office/ole/archive) self-skip because the sentinel path does not exist;
        the content-based analyzers (strings, pe header, capability, yara,
        script, secrets, deobfuscate, carver, entropy) all run normally."""
        start = time.perf_counter()
        info = fileinfo.inspect_bytes(data, name)
        result = ScanResult(info=info)
        self._run_analyzers(info, data, result)
        result.duration_ms = (time.perf_counter() - start) * 1000
        return result

    def scan(self, path: str | Path) -> ScanResult:
        start = time.perf_counter()
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Not a file: {path}")

        info = fileinfo.inspect(path)
        result = ScanResult(info=info)

        # Known-good allowlist short-circuits everything.
        if info.sha256 in self.allowlist:
            result.findings.append(Finding(
                analyzer="allowlist", title="Hash is on the known-good allowlist",
                severity=Severity.INFO, category="allowlist",
                detail="SHA-256 matched an entry in ~/.hawkscan/allowlist.txt.",
            ))
            result.verdict = Verdict.CLEAN
            result.duration_ms = (time.perf_counter() - start) * 1000
            return result

        # Known-bad denylist forces a malicious verdict (instant offline hit).
        if info.sha256 in self.denylist:
            result.findings.append(Finding(
                analyzer="denylist", title="Hash is on the known-bad denylist",
                severity=Severity.CRITICAL, category="denylist",
                detail="SHA-256 matched an entry in ~/.hawkscan/denylist.txt.",
            ))
            result.raw_score = result.score = 200  # force the Malicious band
            result.verdict = Verdict.MALICIOUS
            result.duration_ms = (time.perf_counter() - start) * 1000
            return result

        # Labelled hash database (e.g. imported threat-intel hashes).
        label = self.hashdb.get(info.sha256)
        if label:
            malicious = label.lower() not in ("clean", "benign", "good")
            result.findings.append(Finding(
                analyzer="hashdb",
                title=f"Hash in database: {label}",
                severity=Severity.CRITICAL if malicious else Severity.INFO,
                category="hashdb",
                detail="SHA-256 matched ~/.hawkscan/hashdb.txt.",
            ))
            if malicious:
                result.raw_score = result.score = 200
                result.verdict = Verdict.MALICIOUS
                result.duration_ms = (time.perf_counter() - start) * 1000
                return result

        # Oversized files: identify only, skip the full-read analyzers.
        if info.size > self.max_scan_size:
            result.findings.append(Finding(
                analyzer="engine", title="File too large for deep analysis",
                severity=Severity.INFO, category="coverage",
                detail=f"{info.size:,} bytes exceeds the {self.max_scan_size:,}-byte "
                       "scan limit; only hashing/identification was performed. "
                       "Raise with --max-size.",
            ))
            if info.ext_mismatch:
                result.findings.append(self._mismatch_finding(info))
            result.duration_ms = (time.perf_counter() - start) * 1000
            return result

        ctx_content = None
        if info.size <= 64 * 1024 * 1024:
            ctx_content = path.read_bytes()

        self._run_analyzers(info, ctx_content, result)
        result.duration_ms = (time.perf_counter() - start) * 1000
        return result

    def _run_analyzers(self, info, content, result: ScanResult) -> None:
        """Shared core: run analyzers over the content, aggregate findings into a
        verdict. Used by both scan() (from a path) and scan_bytes() (in-memory)."""
        from ..analyzers.base import AnalysisContext

        ctx = AnalysisContext(info=info, content=content)
        ctx.cache["rules_dir"] = self.rules_dir
        ctx.cache["extract_dir"] = self.extract_dir

        # An extension/type mismatch is itself a finding (masquerading).
        if info.ext_mismatch:
            result.findings.append(self._mismatch_finding(info))

        for cls in self.analyzer_classes:
            inst = cls()
            if not cls.is_available():
                result.analyzers_skipped[cls.name] = (
                    cls.unavailable_reason or "optional dependency not installed"
                )
                continue
            try:
                if not inst.applies(ctx):
                    continue
                produced = list(inst.analyze(ctx))
                result.findings.extend(produced)
                result.analyzers_run.append(cls.name)
            except Exception as exc:  # one analyzer must never sink the scan
                result.errors[cls.name] = f"{type(exc).__name__}: {exc}"
                result.traces[cls.name] = traceback.format_exc()

        # Surface structured capability + ATT&CK data computed by the analyzer.
        caps = ctx.cache.get("capabilities")
        if caps:
            addrs = ctx.cache.get("api_addrs") or {}
            result.capabilities = {
                cat: {
                    "apis": cap.apis,
                    "techniques": cap.techniques,
                    "addresses": {a: addrs[a] for a in cap.apis if a in addrs},
                }
                for cat, cap in caps.items()
            }
        result.mitre = ctx.cache.get("mitre") or {}

        result.findings = self._dedup(result.findings)
        result.raw_score, result.score = self._score(result.findings)
        result.verdict = score_to_verdict(result.score)

        # Verdict caps for strong benign context. Both cap heuristic-only
        # verdicts to Low Risk; a CRITICAL finding (known-bad YARA, EICAR) or a
        # YARA match always bypasses, and denylist/hashdb short-circuit earlier.
        if result.verdict > Verdict.LOW_RISK:
            has_critical = any(f.severity >= Severity.CRITICAL for f in result.findings)
            has_yara = any(f.analyzer == "yara" for f in result.findings)

            # (a) Validly-signed binaries (e.g. catalog-signed system DLLs that
            # legitimately import injection APIs) should not be flagged.
            signed_valid = any(
                f.analyzer == "pe" and f.category == "signature"
                and f.title.startswith("Digitally signed (valid)")
                for f in result.findings)
            # (b) Inert documents/data (markdown, text, logs, config) have no
            # execution vector; keyword/IOC/rule hits there are descriptive
            # (security docs, detection rules) rather than behavioural, so only a
            # CRITICAL hit bypasses their cap.
            inert_doc = info.extension in _INERT_DOC_EXTS

            cap = why = None
            if not has_critical:
                if inert_doc:
                    cap, why = True, "non-executable document/data file"
                elif signed_valid and not has_yara:
                    cap, why = True, "file carries a valid signature"
            if cap:
                result.findings.append(Finding(
                    analyzer="engine",
                    title=f"Verdict capped: {why}",
                    severity=Severity.INFO, category="context",
                    detail="Heuristic findings present but the context is strongly "
                           "benign; verdict capped to Low Risk."))
                result.verdict = Verdict.LOW_RISK

    @staticmethod
    def _mismatch_finding(info: "fileinfo.FileInfo") -> Finding:
        return Finding(
            analyzer="fileinfo",
            title="File extension does not match content",
            severity=Severity.MEDIUM,
            category="masquerading",
            detail=(
                f"Extension '{info.extension}' but content is {info.file_type} "
                f"({info.description}). Mislabeled files are a common delivery trick."
            ),
        )

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        """Drop exact-duplicate findings (same analyzer+title) so identical
        evidence isn't double-counted toward the score."""
        seen: set[tuple[str, str]] = set()
        out: list[Finding] = []
        for f in findings:
            key = (f.analyzer, f.title)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    @staticmethod
    def _score(findings: list[Finding]) -> tuple[int, int]:
        """Return (raw_score, capped_score). Each category's contribution is
        capped so one theme (e.g. many YARA signature hits) can't alone run the
        score to absurd values, while still allowing it to reach 'malicious'."""
        raw = 0
        per_cat: dict[str, int] = {}
        for f in findings:
            raw += int(f.severity)
            per_cat[f.category] = per_cat.get(f.category, 0) + int(f.severity)
        capped = sum(min(v, CATEGORY_SCORE_CAP) for v in per_cat.values())
        return raw, capped
