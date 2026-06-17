#!/usr/bin/env python3
"""Measure HawkScan detection accuracy against a labelled sample corpus.

Point it at a directory of known-malicious files and a directory of known-benign
files; it scans each, treats any verdict at/above the threshold as "flagged
malicious", and reports true/false positives/negatives plus precision, recall
and accuracy.

    python tools/benchmark.py --malicious ./mal --benign ./clean

Use this against REAL samples only inside a disposable analysis VM. It performs
static analysis (no execution) but you are still handling live malware.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Allow running from the repo root without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hawkscan.core.engine import Engine          # noqa: E402
from hawkscan.core.findings import Verdict        # noqa: E402


def _iter_files(d: Path):
    return (f for f in d.rglob("*") if f.is_file()) if d else iter(())


def run(malicious: Path, benign: Path, threshold: Verdict, rules: Path | None):
    engine = Engine(rules_dir=rules)
    tp = fp = tn = fn = errors = 0
    misses, false_alarms = [], []
    start = time.perf_counter()

    for f in _iter_files(malicious):
        try:
            v = engine.scan(f).verdict
        except Exception:
            errors += 1
            continue
        if v >= threshold:
            tp += 1
        else:
            fn += 1
            misses.append(str(f))

    for f in _iter_files(benign):
        try:
            v = engine.scan(f).verdict
        except Exception:
            errors += 1
            continue
        if v >= threshold:
            fp += 1
            false_alarms.append(str(f))
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    print(f"\nHawkScan benchmark (threshold >= {threshold.label})")
    print("-" * 48)
    print(f"  malicious scanned : {tp + fn}")
    print(f"  benign scanned    : {tn + fp}")
    print(f"  errors            : {errors}")
    print(f"  true positives    : {tp}")
    print(f"  false negatives   : {fn}  (missed)")
    print(f"  true negatives    : {tn}")
    print(f"  false positives   : {fp}  (false alarms)")
    print("-" * 48)
    print(f"  detection (recall): {recall:6.1%}")
    print(f"  precision         : {precision:6.1%}")
    print(f"  accuracy          : {accuracy:6.1%}")
    print(f"  F1 score          : {f1:6.3f}")
    print(f"  elapsed           : {time.perf_counter() - start:.1f}s")
    if misses:
        print(f"\n  missed ({len(misses)}):")
        for m in misses[:20]:
            print(f"    - {m}")
    if false_alarms:
        print(f"\n  false alarms ({len(false_alarms)}):")
        for m in false_alarms[:20]:
            print(f"    - {m}")
    return 0


def main():
    p = argparse.ArgumentParser(description="HawkScan accuracy benchmark.")
    p.add_argument("--malicious", type=Path, help="Directory of known-bad samples.")
    p.add_argument("--benign", type=Path, help="Directory of known-good files.")
    p.add_argument("--threshold", default="suspicious",
                   choices=[v.name.lower() for v in Verdict],
                   help="Verdict at/above which a file counts as flagged.")
    p.add_argument("--rules", type=Path, help="Extra YARA rules directory/tree.")
    args = p.parse_args()
    if not args.malicious and not args.benign:
        p.error("provide --malicious and/or --benign")
    return run(args.malicious, args.benign, Verdict[args.threshold.upper()],
               args.rules)


if __name__ == "__main__":
    raise SystemExit(main())
