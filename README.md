# HawkScan

HawkScan is an offline, explainable malware triage scanner. You point it at any
file, of any type, on any operating system, and it tells you whether the file
looks malicious and, more importantly, exactly why.

It is deliberately different from services like VirusTotal. It does not upload
your files anywhere, it does not aggregate third party antivirus engines, and
it works completely offline. Instead it parses the file itself, runs structural,
heuristic and signature based checks, and returns a weighted, auditable verdict
that you can defend line by line.

## What it is and is not

HawkScan performs static and heuristic analysis. It inspects a file without
running it.

It does:
- Identify the true file type and compute cryptographic hashes.
- Parse the structure of common formats (Windows PE, Linux ELF, macOS Mach-O,
  Office documents, PDF, scripts, archives).
- Score suspicious traits and known signatures into a clear verdict.

It does not:
- Execute the file or observe its runtime behaviour (no sandbox).
- Disassemble or decompile code.
- Guarantee a file is safe. A Clean verdict means no static red flags were
  found, not that the file is harmless.

This makes it fast, safe to run on any machine, and fully explainable, which is
exactly what you want for first pass triage.

## How to install

The core engine has no required dependencies and runs on a stock Python 3.9 or
newer install. Optional libraries unlock deeper analysis and are detected
automatically when present.

```bash
# Core only
pip install -e .

# Full analysis (PE imports, YARA matching, Office macro extraction)
pip install -e ".[full]"
```

If an optional library is missing, the matching analyzer is skipped with a note
rather than failing the scan.

## How to run it

```bash
# Scan a single file
hawkscan suspicious.exe

# Scan several files at once
hawkscan file1.dll invoice.pdf script.ps1

# Scan a folder, including subfolders
hawkscan -r ./downloads

# Show only files that are at least suspicious
hawkscan -r ./downloads --min-verdict suspicious

# Machine readable output for pipelines
hawkscan sample.bin --json

# Write a self-contained HTML report
hawkscan sample.bin --html report.html

# Return a non-zero exit code for automation or CI gates
hawkscan -r ./build --fail-on likely_malicious

# Use an additional directory of YARA rules
hawkscan --rules ./my_rules sample.bin

# Carve embedded files (hidden PE/ELF/ZIP) out of a carrier
hawkscan dropper.pdf --extract ./carved
```

If you have not installed it as a command yet, you can always run it as a
module from the project folder:

```bash
python -m hawkscan <file>
```

### Updating the signature set

HawkScan ships with a small set of built in YARA rules. To raise real world
coverage, download the community YARA-Forge ruleset (thousands of rules). The
rules are cached per user and picked up automatically on the next scan.

```bash
hawkscan --update-rules            # core tier, highest confidence
hawkscan --update-rules extended   # broader coverage
hawkscan --update-rules full       # everything, higher false positive rate
```

## How to read the result

Every scan prints the file identity, a verdict, a score, a confidence level, and
the evidence behind the verdict.

```
VERDICT: MALICIOUS   (score 145 (capped from 300), confidence high)

Evidence:
 [High    ] (script/execution) PowerShell Invoke-Expression
 [High    ] (yara/execution)   YARA rule match: download and execute cradle
 [Medium  ] (strings/network)  Network download primitive
```

- Verdict is the bottom line: Clean, Low Risk, Suspicious, Likely Malicious or
  Malicious.
- Score is the total weight of all evidence.
- Confidence reflects how strong and corroborated the evidence is.
- Evidence lists each finding with its analyzer, category and reason, so the
  verdict is never a black box.

## How it works

Each file goes through five stages.

1. Identify. The file is hashed (MD5, SHA1, SHA256) and its true type is
   detected from magic bytes, not from the extension. A file whose extension
   disagrees with its real content is flagged as masquerading.
2. Route. Based on the real type, the file is sent to the relevant analyzers.
3. Analyze. Each analyzer looks for its own indicators and emits findings. Every
   finding carries a severity weight (Info, Low, Medium, High, Critical).
4. Score. The weights are summed. Identical findings are de-duplicated, and no
   single category can dominate the verdict (the report shows the raw and the
   capped score for transparency).
5. Verdict. The capped score maps to a verdict band, and all evidence is shown.

Because the verdict is simply the sum of named findings, you can audit every
decision and tune the thresholds in one place.

## What it implements

| Analyzer | What it looks for |
|----------|-------------------|
| File identity | Hashes, true type, extension versus content mismatch |
| Entropy | Packing, encryption or compression via Shannon entropy |
| Strings | Embedded URLs and IPs, download and execution primitives, persistence, ransomware and spyware indicators |
| PE | Dangerous Windows API imports, packer sections, section entropy, missing signature |
| ELF | Architecture, ptrace anti debugging, LD_PRELOAD and cron persistence |
| Mach-O | File type, missing code signature, LaunchAgent and LaunchDaemon persistence |
| Office | VBA macros, auto execute triggers, shell and download calls inside macros |
| PDF | JavaScript, OpenAction, Launch actions, embedded files, name obfuscation |
| Script | Base64 payloads, character code obfuscation, dynamic execution, hidden window flags |
| Archive | Double extension lures, encrypted archives, decompression bombs, executable members |
| Android | APK and DEX analysis: categorizes requested permissions (high-risk, dangerous) and flags suspicious APIs (SMS fraud, dynamic code loading, accessibility abuse, device-admin, IMEI/IMSI theft, command execution) |
| Capability | Groups imported APIs into behavioural categories (networking, injection, keylogging, persistence...) and maps them to MITRE ATT&CK techniques. The category inventory is informational; high confidence API combinations (such as the process injection triad) drive the score |
| RTF | Detects embedded OLE objects, auto-updating objects, and exploit carriers (Equation Editor CVE-2017-11882/0802, OLE2Link CVE-2017-0199, Packager droppers) |
| Binary profile | Identifies the compiler/runtime of a binary (Go, .NET, Rust, Nim, PyInstaller, AutoIt) to focus follow-up analysis |
| Carver | Finds and extracts executables and archives (PE/ELF/ZIP/...) embedded at a non-zero offset inside a carrier file, a common dropper technique. Embedded PEs are sized from their headers so extraction captures the whole payload |
| YARA | Signature matching from the built in and community rule sets |

The capability and MITRE ATT&CK output gives you a quick behavioural profile of a
binary: what it can do, and which adversary techniques those abilities map to.

## Reducing false positives

- Allowlist known good files by putting their SHA256 hashes (one per line) in
  `~/.hawkscan/allowlist.txt`. Matching files are reported Clean immediately.
- Per category score capping prevents one theme of evidence from maxing the
  verdict on its own.
- Duplicate evidence is removed before scoring.

## Performance

- Compiled YARA rules are cached on disk, so large rule sets compile once and
  load in milliseconds on later scans.
- Files larger than 256 MiB are identified but skip deep analysis. Override the
  limit with `--max-size MB`.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite runs against the core engine with no optional dependencies, on
Linux and Windows across Python 3.11 to 3.13, through continuous integration.

## Limitations

- Static only. It cannot see behaviour that appears only at runtime, such as
  packed, encrypted or fileless payloads. A sandbox would be required for that.
- Signature checking covers embedded Authenticode only, so some validly signed
  Windows binaries are reported as unsigned at low severity.
- Archives are inspected at the member listing level. Their contents are not yet
  scanned recursively.

## License

MIT
