# HawkScan

HawkScan is an offline, explainable malware triage scanner. Point it at any file,
of any type, on any operating system, and it tells you whether the file looks
malicious and, more importantly, exactly why.

It is deliberately different from cloud services such as VirusTotal. By default it
does not upload your files anywhere, does not depend on third party antivirus
engines, and works completely offline. It parses the file itself, runs structural,
heuristic, capability and signature based checks, and returns a weighted,
auditable verdict you can defend finding by finding.

## Highlights

- 23 analyzers covering Windows, Linux, macOS, Android, iOS, documents, archives,
  email, network captures and cloud artefacts.
- Capability categorisation mapped to MITRE ATT&CK techniques.
- Unpacking and deobfuscation layer that recovers and re-scans hidden payloads.
- Explainable weighted verdict with built in false positive controls.
- 68 original YARA rules across 10 packs, plus optional community rules.
- Text, JSON and self contained HTML reports.
- Optional, opt-in extras: dynamic sandbox analysis, VirusTotal lookup, AI summary
  and a local web UI.
- Zero required dependencies for the core engine. 102 automated tests, CI on Linux
  and Windows.

## What it is and is not

HawkScan performs static and heuristic analysis by default. It inspects a file
without running it (dynamic analysis is a separate, opt-in module).

It does:

- Identify the true file type and compute cryptographic and fuzzy hashes.
- Parse the structure of common formats and binaries.
- Score suspicious traits, capabilities and signatures into a clear verdict.

It does not:

- Execute a file unless you explicitly opt in to the VM gated dynamic module.
- Guarantee a file is safe. A Clean verdict means no static red flags were found,
  not that the file is harmless.

## Installation

The core engine has no required dependencies and runs on a stock Python 3.9 or
newer install. Optional libraries unlock deeper analysis and are detected
automatically when present.

```bash
# Core only (works anywhere)
pip install -e .

# Full static analysis (PE imports, YARA, Office macros)
pip install -e ".[full]"

# Optional dynamic analysis tooling (psutil, frida)
pip install -e ".[dynamic]"

# Optional fuzzy hashing
pip install tlsh
```

If an optional library is missing, the matching analyzer is skipped with a note
rather than failing the scan.

## Usage

```bash
# Scan one or more files
hawkscan suspicious.exe invoice.pdf

# Scan a folder, recursively, in parallel
hawkscan -r ./downloads --jobs 8

# Show only files that are at least suspicious
hawkscan -r ./downloads --min-verdict suspicious

# Machine readable output for pipelines
hawkscan sample.bin --json

# Self contained HTML report
hawkscan sample.bin --html report.html

# Carve embedded files (hidden PE/ELF/ZIP) out of a carrier
hawkscan dropper.pdf --extract ./carved

# Hash only lookup against the local allowlist/denylist/hash DB
hawkscan --hashscan suspicious.exe

# Import threat intel hashes into the local database
hawkscan --import-hashes iocs.txt --label "Emotet"

# Use an additional directory or tree of YARA rules
hawkscan --rules ./my_rules sample.bin

# Continuous integration gate (non zero exit at or above a band)
hawkscan -r ./build --fail-on likely_malicious
```

It accepts any file type and routes it to the relevant analyzers:

```bash
hawkscan document.docm        # Office macros / auto-exec
hawkscan exploit.rtf          # RTF object exploits (e.g. Equation Editor)
hawkscan invoice.pdf          # PDF JavaScript / launch actions
hawkscan stager.ps1           # script obfuscation, download cradles, VBE/JSE
hawkscan shortcut.lnk         # LNK launching an interpreter / download
hawkscan phish.eml            # SPF/DKIM/DMARC, spoofing, malicious attachments
hawkscan capture.pcap         # DNS/DGA, suspicious TLDs, C2 beaconing
hawkscan app.apk app.ipa      # Android/iOS package analysis
hawkscan deploy.sh            # leaked cloud keys, IMDS theft, container/k8s abuse
```

Run as a module without installing:

```bash
python -m hawkscan <file>
```

### Optional, opt-in features

These are off by default and never affect the offline core.

```bash
# VirusTotal reputation by hash only (the file is never uploaded); needs VT_API_KEY
hawkscan sample.exe --vt

# Plain-language AI summary; needs the anthropic package and ANTHROPIC_API_KEY
hawkscan sample.exe --ai

# Local, offline web UI (drag and drop) on 127.0.0.1
hawkscan --ui

# Dynamic analysis - runs the sample. ONLY inside a disposable VM.
# Requires HAWKSCAN_SANDBOX=1 plus both --dynamic and --detonate.
HAWKSCAN_SANDBOX=1 hawkscan sample.exe --dynamic --detonate --dynamic-method auto
```

Dynamic tracers (`--dynamic-method`): monitor, strace, Frida API hooking, and ADB
for Android. See `docs/dynamic-analysis.md` for safe VM setup.

### Tuning

Drop a `hawkscan.toml` in the working directory (or `~/.hawkscan/config.toml`)
to adjust verdict thresholds and the per-category score cap without editing code:

```toml
[thresholds]
suspicious = 50
malicious = 160

[scoring]
category_cap = 100
```

### Updating community rules

HawkScan ships with 68 original YARA rules. To add the community YARA-Forge set
(thousands of rules, cached per user, never committed to the repository):

```bash
hawkscan --update-rules            # core tier, highest confidence
hawkscan --update-rules extended   # broader coverage
```

## How to read the result

```
VERDICT: MALICIOUS   (score 250, confidence high)

Evidence:
 [High    ] (capability/Process Injection) Classic process injection
 [High    ] (yara/c2)                       YARA rule match: Cobalt Strike beacon
 [Medium  ] (strings/network)               Network download primitive

Capabilities:
 - Process Injection: WriteProcessMemory 0x..., CreateRemoteThread 0x...

MITRE ATT&CK:
 - T1055   Process Injection
 - T1056.001  Keylogging
```

- Verdict is the bottom line: Clean, Low Risk, Suspicious, Likely Malicious or
  Malicious.
- Score is the total weight of all evidence (capped per category so one theme
  cannot dominate).
- Confidence reflects how strong and corroborated the evidence is.
- Evidence, capabilities and ATT&CK techniques are listed so the verdict is never
  a black box.

## How it works

Each file goes through five stages: identify (hash and true type), route to the
relevant analyzers, analyze (each emits weighted findings), score (sum the
weights with de-duplication and per category caps), and verdict (map the score to
a band and show all the evidence). Because the verdict is the sum of named
findings, every decision is auditable and the thresholds are tuned in one place.

## Analyzers

| Analyzer | What it looks for |
|----------|-------------------|
| File identity | Hashes (MD5/SHA1/SHA256), fuzzy hash (TLSH), true type, extension/content mismatch |
| Entropy | Packing, encryption or compression |
| Strings | Embedded URLs/IPs, download and execution primitives, persistence, ransomware and spyware indicators |
| Secrets and cloud | Leaked AWS/GCP/Azure credentials, private keys, tokens, IMDS theft, container escape, Kubernetes and cloud exfil abuse |
| PE (Windows) | Imports with addresses, exports (reflective loaders, proxying), sections and entropy, packers, signature verification (embedded and catalog), overlay, resources, version info, imphash, rich header, TLS callbacks |
| .NET | CLR metadata parsing, IL user strings, symbol obfuscation detection |
| ELF (Linux) | Architecture, ptrace anti debugging, persistence and rootkit indicators |
| Mach-O (macOS) | File type, code signature, persistence indicators |
| Capability | Groups 149 APIs into behavioural categories and maps them to MITRE ATT&CK |
| Binary profile | Compiler/runtime detection (Go, .NET, Rust, Nim, PyInstaller, AutoIt) |
| Office | VBA macros, auto execute, encrypted documents, OneNote droppers |
| OLE / MSG | Legacy OLE stream walk, embedded-object detection, Outlook .msg headers and attachments |
| Steganography | Data appended after an image's real EOF and polyglot files (image valid as a second type) |
| PDF | JavaScript, OpenAction, Launch, embedded files, obfuscation |
| RTF | Embedded OLE objects, Equation Editor and OLE2Link exploits, Packager droppers |
| LNK | Windows shortcut header parsing; embedded command-interpreter/download detection |
| Script | Base64/hex payloads, obfuscation, dynamic execution, encoded (VBE/JSE) scripts |
| Archive | Double extension lures, encrypted archives, decompression bombs |
| Email | EML headers (SPF/DKIM/DMARC), sender spoofing, malicious attachments |
| PCAP | Contacted IPs, DNS queries, HTTP hosts, suspicious TLD and DGA domains, C2 beaconing, cleartext credentials |
| Android / iOS | APK/DEX permissions and suspicious APIs, iOS app package detection |
| Carver | Finds and extracts executables and archives embedded inside a carrier |
| Deobfuscation | Unpacks UPX and decodes base64/hex layers, then re-scans the recovered payload |
| YARA | Signature matching from the bundled and optional community rule sets |

## Detection content

68 original YARA rules across 10 packs: Windows techniques, Linux/ELF, macOS,
mobile (Android and iOS), cloud, malicious documents, behaviours and families
(infostealers, ransomware, miners, RATs, webshells, Cobalt Strike and more). The
capability database maps 149 Windows and Linux APIs to MITRE ATT&CK techniques.
Community coverage is available on demand via `--update-rules` (YARA-Forge) or by
pointing `--rules` at any rule tree.

## Reducing false positives

- Allowlist known good files by SHA-256 in `~/.hawkscan/allowlist.txt`.
- Denylist or label known bad hashes in `~/.hawkscan/denylist.txt` and
  `~/.hawkscan/hashdb.txt`.
- Per category score capping and duplicate evidence removal keep one theme from
  inflating the verdict.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

102 tests run on Linux and Windows across Python 3.11 to 3.13 through continuous
integration, including an end to end detection regression corpus and rule compile
guards. A benchmark harness (`tools/benchmark.py`) measures precision and recall
against a labelled malicious/benign corpus.

## Limitations

- Static by default. Behaviour that appears only at runtime needs the opt-in
  dynamic module in a VM.
- Detection depth grows with use; validate accuracy against a real corpus with
  `tools/benchmark.py` before relying on it operationally.

## License

MIT
