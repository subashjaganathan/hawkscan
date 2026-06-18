# Changelog

All notable changes to HawkScan are documented here.

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
