# Changelog

All notable changes to HawkScan are documented here.

## [1.1.0]

### Added
- **OLE / Outlook .msg analyzer**: walks legacy OLE compound-document streams and
  parses .msg email (subject, transport headers for SPF/DKIM/DMARC, attachments),
  flagging embedded-object streams and risky/executable attachments.
- **Steganography / polyglot detector**: flags data appended after an image's
  real EOF (smuggled payloads) and polyglot files valid as a second type.
- **HTML / phishing rule pack**: HTML smuggling, credential-harvesting forms,
  eval/unescape droppers, ASP.NET/JSP webshells.
- **Follina (CVE-2022-30190) MSDT** maldoc rule.
- Now 23 analyzers and 68 rules across 10 packs.

## [1.0.1]

### Security
- Web UI now sanitises uploaded filenames to a safe basename, preventing a
  path-traversal write outside the temporary directory.

### Added
- Tunable configuration via `hawkscan.toml` / `~/.hawkscan/config.toml`
  (verdict thresholds and per-category score cap); defaults unchanged.

### Changed
- File contents are read once and cached per scan, so large files are no longer
  re-read by every analyzer.

## [1.0.0]

First stable release. Consolidates the full feature set: 21 analyzers spanning
Windows, Linux, macOS, Android, iOS, documents, archives, email, network
captures and cloud artefacts; capability + MITRE ATT&CK mapping; unpacking and
deobfuscation; 63 original YARA rules across 9 packs; explainable weighted
verdicts with false-positive controls; text/JSON/HTML reports; and opt-in
dynamic, VirusTotal, AI and web-UI features. No functional changes from 0.8.0 -
this release marks the API and behaviour as stable.

## [0.8.0]

### Added
- **LNK (Windows shortcut) analysis**: parses the Shell Link header and recovers
  embedded command lines, flagging shortcuts that launch interpreters/downloads.
- **PE section anomalies**: writable+executable (RWX) sections and memory-only
  sections (packer unpacking stubs).
- **PCAP beaconing detection**: flags near-constant-interval connections to a
  destination (C2 beaconing) via timing-regularity analysis.
- **Encoded-script detection**: flags Microsoft Script Encoder (VBE/JSE) content.

## [0.7.0]

### Added
- **Secrets & cloud-threat analyzer**: detects leaked cloud credentials (AWS/GCP/
  Azure keys, private keys, GitHub/Slack tokens, JWTs), instance-metadata (IMDS)
  credential theft, container escape and Kubernetes attacks, and cloud CLI/exfil
  abuse - across any file type.
- **Cloud YARA pack**: IMDS theft, cloud credential-file targeting, container
  escape, Kubernetes secret abuse, cloud cryptojacking, exfil-to-storage.
- **Expanded macOS coverage**: infostealer (fake password prompt + exfil) and
  dylib-hijack rules.
- **Mobile coverage**: iOS app (.ipa) type detection and a mobile YARA pack
  (Android banking overlays/RAT, iOS jailbreak/private-API and config-profile abuse).
- Bundled rule set now 63 rules across 9 packs (Windows, Linux, macOS, mobile,
  cloud, documents, behaviours, families).

## [0.6.1]

### Added
- **.NET (managed PE) analysis**: parses the CLR metadata and recovers #US (IL
  user strings) and #Strings (type/method names) directly, surfacing URLs,
  commands and mutexes from .NET malware, and flagging likely symbol obfuscation.

### Fixed
- Overlay detection no longer counts the Authenticode certificate as appended
  payload, eliminating a false positive on every embedded-signed binary.
- OriginalFilename mismatch downgraded to LOW and now skips placeholder values
  (e.g. "unknown_file"), so legitimately renamed files are not flagged.

## [0.6.0]

### Added
- **Unpacking / deobfuscation layer**: recovers a hidden second stage and
  re-scans it, so a benign-looking wrapper whose real payload is packed or
  encoded is still caught. UPX-unpacks PEs (if the `upx` tool is present) and
  decodes large base64/hex (incl. UTF-16 PowerShell) blobs in scripts.
- **PE identity & depth**: imphash and rich-header fingerprints (for family
  clustering), TLS-callback detection (early-execution/anti-analysis), and
  best-effort certificate signer extraction.
- **Fuzzy hashing** (TLSH) in file identity when the optional `tlsh` library is
  installed, for sample similarity clustering.

## [0.5.0]

### Added
- **VirusTotal enrichment** (`--vt`): opt-in reputation lookup by SHA-256 hash
  only (the file is never uploaded). Gated on VT_API_KEY; stdlib urllib, no new
  dependency. Detections fold into the verdict. This was the last unimplemented
  function from the reference tool's flag set; HawkScan now covers them all.

## [0.4.0]

### Added
- **Local web UI** (`--ui`): offline drag-and-drop scanning on 127.0.0.1, returns
  the HTML report. Stdlib only, no Flask.
- **Authenticode signature verification** (Windows): real validity check for
  embedded *and* catalog-signed binaries via ctypes (WinVerifyTrust + catalog
  APIs); degrades to presence-only off-Windows. Fixes catalog-signed system
  binaries previously shown as "not signed".
- **Offline hash database**: `--hashscan` (hash-only lookup mode) and
  `--import-hashes FILE --label` to bulk-load threat-intel hashes; matches force
  a Malicious verdict with the label shown.
- **Resource & version-info analysis** for PE: enumerates resources, extracts
  version strings, and flags OriginalFilename masquerading.
- **Optional AI summary** (`--ai`): plain-language analyst summary via the Claude
  API. Opt-in, gated on the SDK + API key; the only feature that uses the network.

## [0.3.1]

### Added
- Per-API addresses in the capability output (text and HTML), giving import-level
  detail comparable to deeper analysis tools.
- Capability categories expanded with Collection (clipboard) and Defense Evasion
  (indicator removal / time-based) buckets, plus more discovery APIs.

## [0.3.0]

### Added
- Offline known-bad **hash denylist** (`~/.hawkscan/denylist.txt`) that forces a
  Malicious verdict, complementing the existing known-good allowlist.
- **Parallel folder scanning** (`--jobs`, auto by default) for static scans;
  dynamic analysis remains sequential for safety.
- **PE overlay and resource analysis**: flags appended overlay data (with
  entropy) and detects embedded PE files inside the resource section.
- **Benchmark harness** (`tools/benchmark.py`) to measure detection accuracy
  (precision/recall/F1) against a labelled malicious/benign corpus.
- HTML report now includes a **dynamic-analysis section** (processes, dropped
  files, network, API calls, syscalls).
- Rule-compile failures are now **surfaced as a finding** instead of being
  silently dropped by the per-file fallback.

### Changed
- Bundled YARA rule set grown to 51 original rules across 7 packs (Windows,
  Linux, macOS, documents, behaviours) plus the capability API database at 140
  functions.

### Fixed
- Four bundled rule packs (families/linux/macos/maldoc) were failing to compile
  (unreferenced strings / inline-nocase syntax) and being silently dropped; all
  now compile and are active. Added `tests/test_rules.py` to guard against
  regressions.

## [0.2.0]

### Added
- API capability categorization and MITRE ATT&CK mapping.
- Self-contained HTML report (`--html`).
- Android APK/DEX, RTF, OneNote, email (EML) and PCAP analysis.
- Embedded-file carving (`--extract`).
- Optional VM-gated dynamic analysis (monitor / strace / Frida / ADB).
- Detection regression corpus and dynamic-analysis docs.

## [0.1.0]

### Added
- Initial release: offline, explainable static malware scanner with PE/ELF/
  Mach-O, Office, PDF, script, archive, entropy, strings and YARA analyzers;
  weighted verdict scoring; text/JSON output; YARA-Forge rule updates.
