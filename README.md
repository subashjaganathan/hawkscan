# HawkScan

Offline, explainable malware scanner for **any file type on any OS**.

HawkScan is **not** a VirusTotal clone. It does not upload your files, does not
aggregate third-party antivirus engines, and works fully offline. Instead it
*parses* each file, runs structural + heuristic + YARA analysis, and returns a
**verdict with the evidence behind it** — a weighted, auditable score rather
than a black-box yes/no.

```
  VERDICT: MALICIOUS   (score 300, confidence high)

  Evidence:
   [High    ] (script/execution) PowerShell Invoke-Expression
   [High    ] (yara/execution)   YARA rule match: HawkScan_Suspicious_Download_Exec
   [Medium  ] (strings/network)  Network download primitive
   ...
```

## Why it's different

| | VirusTotal | HawkScan |
|---|---|---|
| Network | Uploads file to cloud | 100% offline / local |
| Engine | Aggregates 70+ AV vendors | Own static + heuristic + YARA engine |
| Output | Vendor vote count | Explainable, weighted evidence per finding |
| Privacy | File leaves your machine | Nothing leaves your machine |

## How it works

Each file is hashed and identified by magic bytes, then routed to the relevant
analyzers. Every analyzer emits **Findings** carrying a severity weight; the
engine sums those weights into a score and maps it to a verdict band:

`Clean → Low Risk → Suspicious → Likely Malicious → Malicious`

Because the verdict is just the sum of named findings, you can always see
*why* — and retune the thresholds in one place (`core/findings.py`).

### Analyzers
- **fileinfo** — hashing (MD5/SHA1/SHA256), type detection, extension/content
  mismatch (masquerading) detection
- **entropy** — packing / encryption detection via Shannon entropy
- **pe** — Windows PE: imports, section entropy, packer sections, signatures *(uses `pefile`)*
- **elf** — Linux ELF: header facts + persistence/anti-debug heuristics
- **macho** — macOS Mach-O: header facts + code-signing / persistence heuristics
- **office** — VBA macros, auto-exec, suspicious APIs *(uses `oletools`)*
- **pdf** — active-content keywords (JavaScript, OpenAction, Launch, …)
- **script** — PowerShell/JS/VBS/batch obfuscation + dynamic-eval detection
- **archive** — ZIP members: double-extension lures, encrypted archives, zip bombs
- **strings** — format-agnostic IOC + capability extraction (URLs, IPs, APIs)
- **yara** — rule matching from `rules/` or `--rules` *(uses `yara-python`)*

## Install

The **core engine has zero required dependencies** — it runs on a stock Python
3.9+ install. Optional libraries unlock deeper analysis and light up
automatically when present:

```bash
# Core only (works anywhere)
pip install -e .

# Full power (PE imports, YARA, Office macros)
pip install -e ".[full]"
# or just: pip install pefile yara-python oletools
```

If an optional library is missing, the relevant analyzer is **skipped with a
note** — HawkScan never crashes on a missing dependency.

## Usage

```bash
# Scan one or more files
hawkscan suspicious.exe invoice.pdf

# Scan a directory recursively
hawkscan -r ./downloads

# JSON output (for pipelines / HawkSuite integration)
hawkscan --json sample.bin

# Only report files at/above a band
hawkscan -r ./quarantine --min-verdict suspicious

# CI / automation: non-zero exit if anything reaches a band
hawkscan -r ./build --fail-on likely_malicious

# Use your own YARA rules
hawkscan --rules ./my_rules sample.bin
```

### Updating the community ruleset

HawkScan ships with a handful of built-in YARA rules. To dramatically raise
real-world coverage, download the community [YARA-Forge](https://yarahq.github.io/)
ruleset (thousands of rules). They are cached per-user (`~/.hawkscan/rules/`),
never committed to the repo, and picked up automatically on the next scan:

```bash
hawkscan --update-rules            # 'core' tier (high-confidence, default)
hawkscan --update-rules extended   # broader coverage
hawkscan --update-rules full       # everything (highest FP rate)
```

Run without installing:

```bash
python -m hawkscan <file>
```

## Extending detection

Drop additional `.yar` files into `hawkscan/rules/` (or point `--rules` at your
own directory). A rule may set `meta.severity` (`info|low|medium|high|critical`)
and `meta.category`/`meta.description` to control how it scores and reads.

## Reducing false positives

- **Allowlist known-good files.** Put SHA-256 hashes (one per line, `#` for
  comments) in `~/.hawkscan/allowlist.txt`; matching files are reported Clean
  immediately.
- **Score capping.** No single category (e.g. many YARA signature hits of one
  theme) can dominate the verdict; the report shows the raw vs. capped score.
- **Duplicate evidence is de-duplicated** before scoring.

## Performance & limits

- Compiled YARA rules are cached on disk (`~/.hawkscan/compiled/`), so large
  rulesets compile once and load in milliseconds thereafter.
- Files larger than 256 MiB are hashed/identified but skip deep analysis
  (override with `--max-size MB`).

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

CI runs the core test suite on Linux + Windows across Python 3.11–3.13 with no
optional dependencies, enforcing the "runs on stock Python" contract.

## Known limitations

- No dynamic/sandbox execution — this is a static + heuristic engine, so it
  cannot see behavior that only appears at runtime (packed/encrypted/fileless).
- A "Clean" verdict means "no static red flags found," not "guaranteed safe."
- Signature check detects *embedded* Authenticode only; catalog-signed Windows
  binaries show as "not signed" (low-severity note, never a malicious verdict).
- Archives are inspected at the member-listing level; contents are not yet
  recursively scanned.

## License

MIT
