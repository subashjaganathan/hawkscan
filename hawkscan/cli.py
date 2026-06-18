"""HawkScan command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .core.engine import Engine
from .core.findings import Verdict, Finding, Severity, score_to_verdict
from . import report


def _scan_files(engine, files, jobs: int):
    """Scan files, returning [(path, result|None, error|None)] in input order.

    The first file is scanned sequentially to warm the shared (process-global)
    compiled-YARA cache before workers start, avoiding redundant compiles and
    on-disk cache write races.
    """
    def one(f):
        try:
            return (f, engine.scan(f), None)
        except Exception as exc:  # never let one file sink the batch
            return (f, None, f"{type(exc).__name__}: {exc}")

    if jobs <= 1 or len(files) <= 1:
        return [one(f) for f in files]

    from concurrent.futures import ThreadPoolExecutor
    first = one(files[0])  # warm caches
    rest = files[1:]
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        return [first, *ex.map(one, rest)]


def _gather_files(paths: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            it = path.rglob("*") if recursive else path.glob("*")
            files.extend(f for f in it if f.is_file())
        elif path.is_file():
            files.append(path)
        else:
            print(f"hawkscan: not found: {p}", file=sys.stderr)
    return files


_RISKY_DROP_EXTS = {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs",
                    ".js", ".jar", ".hta", ".lnk"}
_NOTABLE = ("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "bitsadmin", "certutil", "schtasks", "curl", "wget")


def _run_dynamic(res, path, timeout: int, detonate: bool, method: str) -> None:
    """Run dynamic analysis and merge behavioural findings into the result."""
    from .dynamic import run_sample

    sb = run_sample(path, res.info.file_type, timeout=timeout,
                    allow_detonate=detonate, method=method)
    res.dynamic = sb.to_dict()

    if not sb.ran:
        reason = sb.skipped_reason or ("; ".join(sb.notes) if sb.notes else
                                       "no observable behaviour")
        res.findings.append(Finding(
            analyzer="dynamic", title="Dynamic analysis not run",
            severity=Severity.INFO, category="dynamic", detail=reason))
        return

    new: list[Finding] = []
    for call in sb.api_calls:
        notable = any(n in call.lower() for n in
                      ("injection", "writeprocess", "createremote", "virtualalloc",
                       "createprocess", "regsetvalue", "urldownload", "crypt",
                       "telephony", "execution", "dynamic-code"))
        new.append(Finding(
            analyzer="dynamic", title=f"API/behaviour: {call[:80]}",
            severity=Severity.MEDIUM if notable else Severity.LOW,
            category="behaviour", detail="Observed at runtime via API hooking."))
    for sc in sb.syscalls:
        notable = sc in ("ptrace", "execve", "clone", "fork", "mprotect", "connect")
        new.append(Finding(
            analyzer="dynamic", title=f"Syscall: {sc}",
            severity=Severity.LOW if notable else Severity.INFO,
            category="behaviour", detail="Observed via strace."))
    for child in sb.child_processes:
        notable = any(n in child.lower() for n in _NOTABLE)
        new.append(Finding(
            analyzer="dynamic",
            title=f"Spawned process: {child[:80]}",
            severity=Severity.MEDIUM if notable else Severity.LOW,
            category="execution", detail="Child process created at runtime."))
    for f in sb.files_created:
        ext = ("." + f.rsplit(".", 1)[-1].lower()) if "." in f else ""
        new.append(Finding(
            analyzer="dynamic", title=f"Dropped file: {f}",
            severity=Severity.MEDIUM if ext in _RISKY_DROP_EXTS else Severity.INFO,
            category="dropper", detail="File written during execution."))
    for conn in sb.network:
        new.append(Finding(
            analyzer="dynamic", title=f"Network connection: {conn}",
            severity=Severity.MEDIUM, category="network",
            detail="Outbound connection made at runtime."))
    if sb.timed_out:
        new.append(Finding(
            analyzer="dynamic", title="Sample ran until timeout",
            severity=Severity.INFO, category="dynamic",
            detail=f"Did not exit within {timeout}s (long-running/persistent)."))

    res.findings.extend(new)
    res.findings = Engine._dedup(res.findings)
    res.raw_score, res.score = Engine._score(res.findings)
    res.verdict = score_to_verdict(res.score)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hawkscan",
        description="Offline, explainable malware scanner for any file on any OS.",
    )
    p.add_argument("paths", nargs="*", help="File(s) or directory(ies) to scan.")
    p.add_argument("--update-rules", metavar="TIER", nargs="?", const="core",
                   choices=["core", "extended", "full"],
                   help="Download/refresh the YARA-Forge community ruleset "
                        "(core|extended|full; default core) and exit.")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="Recurse into directories.")
    p.add_argument("--jobs", type=int, default=0, metavar="N",
                   help="Parallel scan workers (0 = auto). Forced to 1 with --dynamic.")
    p.add_argument("-j", "--json", action="store_true",
                   help="Emit JSON instead of a text report.")
    p.add_argument("--html", metavar="FILE",
                   help="Write a self-contained HTML report to FILE.")
    p.add_argument("--rules", metavar="DIR",
                   help="Directory of additional YARA (.yar) rules.")
    p.add_argument("--hashscan", action="store_true",
                   help="Hash-only mode: look up file hashes in the local "
                        "allowlist/denylist/hashdb and report, no deep analysis.")
    p.add_argument("--import-hashes", metavar="FILE",
                   help="Append SHA-256 hashes from FILE to the local hash DB.")
    p.add_argument("--label", default="malicious",
                   help="Label to apply with --import-hashes (default: malicious).")
    p.add_argument("--show-info", action="store_true",
                   help="Include informational findings in text output.")
    p.add_argument("--min-verdict", choices=[v.name.lower() for v in Verdict],
                   default="clean",
                   help="Only report files at/above this verdict band.")
    p.add_argument("--fail-on", choices=[v.name.lower() for v in Verdict],
                   help="Exit non-zero if any file reaches this band (for CI/automation).")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress per-file output; print only the summary/JSON.")
    p.add_argument("--max-size", metavar="MB", type=int, default=256,
                   help="Skip deep analysis for files larger than this (MiB). "
                        "Default 256.")
    p.add_argument("--debug", action="store_true",
                   help="Include full analyzer tracebacks in output.")
    p.add_argument("--ui", action="store_true",
                   help="Launch the local web UI (offline, 127.0.0.1).")
    p.add_argument("--ui-port", type=int, default=8000, metavar="PORT",
                   help="Port for the web UI (default 8000).")
    p.add_argument("--ai", action="store_true",
                   help="Append an AI plain-language summary (needs anthropic + "
                        "ANTHROPIC_API_KEY; the only feature that uses the network).")
    p.add_argument("--extract", metavar="DIR",
                   help="Carve embedded files (PE/ELF/ZIP/...) into DIR.")
    p.add_argument("--dynamic", action="store_true",
                   help="DANGER: run the sample and observe its behaviour. Only "
                        "works inside a VM with HAWKSCAN_SANDBOX=1 set.")
    p.add_argument("--detonate", action="store_true",
                   help="Required alongside --dynamic to actually execute the sample.")
    p.add_argument("--dynamic-timeout", metavar="SEC", type=int, default=20,
                   help="Seconds to let a sample run under dynamic analysis.")
    p.add_argument("--dynamic-method", choices=["auto", "monitor", "strace",
                                                "frida", "adb"], default="auto",
                   help="Dynamic tracer: auto (default), monitor, strace (Linux), "
                        "frida (API hooking), adb (Android).")
    p.add_argument("-V", "--version", action="version",
                   version=f"HawkScan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.update_rules:
        from .core.rules_update import update_rules
        try:
            dest = update_rules(args.update_rules)
        except Exception as exc:
            print(f"hawkscan: rule update failed: {exc}", file=sys.stderr)
            return 2
        print(f"Rules updated in {dest}")
        return 0

    if args.import_hashes:
        import re as _re
        from .core.engine import _HASHDB_PATH
        try:
            text = Path(args.import_hashes).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            print(f"hawkscan: cannot read {args.import_hashes}: {exc}", file=sys.stderr)
            return 2
        hashes = sorted(set(_re.findall(r"\b[0-9a-fA-F]{64}\b", text)))
        if not hashes:
            print("hawkscan: no SHA-256 hashes found in file", file=sys.stderr)
            return 2
        _HASHDB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _HASHDB_PATH.open("a", encoding="utf-8") as fh:
            for h in hashes:
                fh.write(f"{h.lower()} {args.label}\n")
        print(f"Imported {len(hashes)} hash(es) labelled '{args.label}' into "
              f"{_HASHDB_PATH}")
        return 0

    if args.ui:
        from . import webui
        webui.serve(port=args.ui_port,
                    rules_dir=Path(args.rules) if args.rules else None)
        return 0

    if not args.paths:
        print("hawkscan: no files to scan (give a path, or use --update-rules)",
              file=sys.stderr)
        return 2

    rules_dir = Path(args.rules) if args.rules else None
    engine = Engine(rules_dir=rules_dir, max_scan_size=args.max_size * 1024 * 1024,
                    extract_dir=Path(args.extract) if args.extract else None)

    files = _gather_files(args.paths, args.recursive)
    if not files:
        print("hawkscan: no files to scan", file=sys.stderr)
        return 2

    if args.hashscan:
        from .core import fileinfo
        hits = 0
        for f in files:
            try:
                h = fileinfo.hash_file(f)[2]  # sha256
            except OSError as exc:
                print(f"hawkscan: {f}: {exc}", file=sys.stderr)
                continue
            if h in engine.allowlist:
                verdict = "ALLOWLISTED (clean)"
            elif h in engine.denylist:
                verdict = "DENYLISTED (malicious)"; hits += 1
            elif h in engine.hashdb:
                verdict = f"HASHDB: {engine.hashdb[h]}"; hits += 1
            else:
                verdict = "unknown"
            print(f"{verdict:28} {h}  {f}")
        return 1 if (args.fail_on and hits) else 0

    min_verdict = Verdict[args.min_verdict.upper()]
    fail_on = Verdict[args.fail_on.upper()] if args.fail_on else None

    # Determine parallelism. Dynamic analysis executes samples, so it is always
    # sequential; otherwise scale to the requested/auto worker count.
    jobs = 1 if args.dynamic else (args.jobs or min(8, (os.cpu_count() or 2)))
    scanned = _scan_files(engine, files, jobs)

    results = []
    worst = Verdict.CLEAN
    json_blobs = []
    for f, res, err in scanned:
        if err is not None:
            print(f"hawkscan: error scanning {f}: {err}", file=sys.stderr)
            continue
        if args.dynamic:
            _run_dynamic(res, f, args.dynamic_timeout, args.detonate,
                         args.dynamic_method)

        results.append(res)
        worst = max(worst, res.verdict)

        if res.verdict < min_verdict:
            continue

        summary = None
        if args.ai:
            from . import ai
            summary = ai.summarize(res.to_dict())

        if args.json:
            blob = res.to_dict(include_traces=args.debug)
            if summary:
                blob["ai_summary"] = summary
            json_blobs.append(blob)
        elif not args.quiet:
            print(report.render_text(res, show_info=args.show_info, debug=args.debug))
            if summary:
                print(f"\n  AI summary:\n  {summary}\n")
            print()

    if args.html:
        from . import report_html
        reported = [r for r in results if r.verdict >= min_verdict] or results
        Path(args.html).write_text(
            report_html.render_html(reported), encoding="utf-8"
        )
        print(f"HTML report written to {args.html}")

    if args.json:
        import json as _json
        payload = json_blobs[0] if len(json_blobs) == 1 else json_blobs
        print(_json.dumps(payload, indent=2))
    elif len(results) > 1:
        # Multi-file summary line.
        counts: dict[str, int] = {}
        for r in results:
            counts[r.verdict.label] = counts.get(r.verdict.label, 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in counts.items())
        print(f"Scanned {len(results)} file(s): {summary}")

    if fail_on is not None and worst >= fail_on:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
