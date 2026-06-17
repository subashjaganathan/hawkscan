"""HawkScan command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core.engine import Engine
from .core.findings import Verdict
from . import report


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
    p.add_argument("-j", "--json", action="store_true",
                   help="Emit JSON instead of a text report.")
    p.add_argument("--rules", metavar="DIR",
                   help="Directory of additional YARA (.yar) rules.")
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

    if not args.paths:
        print("hawkscan: no files to scan (give a path, or use --update-rules)",
              file=sys.stderr)
        return 2

    rules_dir = Path(args.rules) if args.rules else None
    engine = Engine(rules_dir=rules_dir, max_scan_size=args.max_size * 1024 * 1024)

    files = _gather_files(args.paths, args.recursive)
    if not files:
        print("hawkscan: no files to scan", file=sys.stderr)
        return 2

    min_verdict = Verdict[args.min_verdict.upper()]
    fail_on = Verdict[args.fail_on.upper()] if args.fail_on else None

    results = []
    worst = Verdict.CLEAN
    json_blobs = []
    for f in files:
        try:
            res = engine.scan(f)
        except Exception as exc:
            print(f"hawkscan: error scanning {f}: {exc}", file=sys.stderr)
            continue
        results.append(res)
        worst = max(worst, res.verdict)

        if res.verdict < min_verdict:
            continue

        if args.json:
            json_blobs.append(res.to_dict(include_traces=args.debug))
        elif not args.quiet:
            print(report.render_text(res, show_info=args.show_info, debug=args.debug))
            print()

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
