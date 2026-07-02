# Changelog

All notable changes to Hawk Malware Scan are documented here.

## [1.0.0] (rolling)

The project version is pinned at 1.0.0; ongoing fine-tuning is tracked here
rather than by bumping the version on each change.

### Added
- **Emulation-based analysis (optional)** via new `emulate` analyzer:
  - **FLARE FLOSS** integration recovers obfuscated strings (stack/tight/decoded)
    that static extraction misses, then scans them for IOCs and behavioural
    markers - so packed samples that hide C2/URLs/commands behind a string
    decoder still get caught.
  - **Speakeasy** integration emulates a PE's execution (API calls, file/
    registry/network) WITHOUT running it natively - dynamic behaviour with no VM
    and no EDR trigger.
  - Both read the already-on-disk sample (nothing new written) and degrade
    gracefully: the analyzer is skipped with a note when neither engine is
    installed. Enable with `pip install hawk-malware-scan[emulate]`.
- **New YARA rule pack `hawk-malware-scan_linux_threats.yar`** (4 original rules):
  Mirai/Gafgyt-class IoT botnet markers, Linux reverse/bind shell patterns,
  shell-history & system-log wiping (anti-forensics), and SSH-key / cron /
  systemd persistence implants. Conservative multi-indicator conditions,
  verified not to match benign busybox firmware or admin scripts.
  (91 bundled rules across 14 packs.)

<!-- History below was released under incrementing version tags before the
     version was pinned at 1.0.0. -->

## [1.31.0]

### Added
- **New YARA rule pack `hawk-malware-scan_ransomware.yar`** (4 original rules, 83 -> 87
  bundled): recovery-tampering command chains (vssadmin/bcdedit/wbadmin),
  family-specific ransom-note artifacts (WannaCry/LockBit/Ryuk/Conti/REvil/
  Hive/Maze/BlackCat/Phobos), encryption-behaviour combination (crypto API +
  file enumeration + ransom-note text), and cryptominer detection (stratum
  mining-pool protocol + miner markers). Verified to not match benign prose.

## [1.30.0]

### Added
- **New YARA rule pack `hawk-malware-scan_stealers.yar`** (6 original rules, 77 -> 83
  bundled): browser-credential infostealer (browser stores + wallet/exfil),
  clipboard crypto-clipper (clipboard APIs + hardcoded wallet address),
  in-memory shellcode loader (process-injection API triad in a PE), Cobalt
  Strike beacon (default named pipes / reflective loader), keylogger (keystroke
  log markers + capture API), and .NET RAT internal markers. Conservative
  multi-indicator conditions; verified to not match benign prose.

## [1.29.0]

### Added
- **Strings analyzer coverage** (module improvement pass 17): high-signal
  behaviour patterns - Microsoft Defender tampering, AMSI bypass, event-log
  clearing (anti-forensics), UAC-bypass LOLBins, certutil download/decode
  abuse, local account/admin-group manipulation - plus email-address and
  crypto-wallet (Ethereum/Monero) IOC extraction. Plain text stays clean.

## [1.28.0]

### Changed
- **EDR-friendly in-memory analysis**: nested re-scans of recovered payloads
  (deobfuscated stages and archive members) now run entirely in memory via the
  new Engine.scan_bytes() / fileinfo.inspect_bytes(). Hawk Malware Scan no longer writes
  the recovered (often malicious) payload to a temp file during a normal scan,
  so an on-access EDR such as CrowdStrike Falcon cannot quarantine it and abort
  the scan. Detection of the nested payload is unchanged. (Explicit --extract
  still writes carved files on request; UPX auto-unpack still uses the upx CLI.)

## [1.27.0]

### Added
- **Carver signature coverage** (module improvement pass 16): embedded
  Mach-O (validated by filetype), Android DEX, OLE/MSI compound files, CAB,
  XZ and CHM payloads are now carved/flagged in addition to PE/ELF/ZIP/PDF/
  RAR/GZIP/7z. Specific multi-byte magics keep false positives at zero on
  clean images.

## [1.26.0]

### Fixed
- **Stego polyglot false positive**: the polyglot scan matched a bare 2-byte
  "MZ" anywhere in image data, flagging ~every JPEG as a "PE polyglot". PE
  polyglots are now detected via the DOS-stub string and all signatures are
  >=4 bytes/validated (0/20 clean images flagged, was 20/20).

### Added
- BMP and WEBP logical-end parsing for trailing-data/steganography detection.

## [1.25.0]

### Added
- **Binary profiler depth** (module improvement pass 14): named runtime
  packer/protector detection (Themida/WinLicense, VMProtect, ASPack,
  ASProtect, MPRESS, PECompact, Enigma, Obsidium, NsPack, Petite, FSG, Upack,
  PELock, kkrunchy, Armadillo, MoleBox, ExeStealth) and additional runtimes
  (Delphi, Visual Basic 6, Electron/Node). FP-tuned vs 120 signed binaries.

## [1.24.0]

### Added
- **Secrets analyzer coverage** (module improvement pass 13): modern token
  formats - Stripe, GitLab, Shopify, npm, SendGrid, Twilio, Telegram bot,
  Discord webhook, OpenAI, Anthropic, PyPI - plus database connection strings
  with embedded credentials and hardcoded bearer tokens. Distinctive formats
  keep false positives low (plain config files stay clean).

## [1.23.0]

### Added
- **Capability/ATT&CK combinations** (module improvement pass 12): seven new
  high-confidence multi-API patterns that drive the score - anti-debugging
  (T1622), process-enumeration injection recon (T1057), Windows service
  persistence (T1543.003), WinINet/WinHTTP C2 (T1071.001), raw-socket C2
  (T1095), bulk file encryption/ransomware (T1486), and screen/clipboard
  capture (T1113/T1115). FP-tuned against 151 signed system binaries.

## [1.22.0]

### Added
- **LNK analyzer depth** (module improvement pass 11): structured StringData
  parsing recovers the exact COMMAND_LINE_ARGUMENTS, relative path and icon
  location (instead of guessing from loose strings); icon-spoofing detection
  (document/media icon over a shell-launching target); and appended-payload
  detection (large trailing data beyond the shortcut structures).

## [1.21.0]

### Added
- **PCAP analyzer depth** (module improvement pass 10): TLS ClientHello SNI
  extraction (HTTPS C2 destinations are now visible, not just port-80 hosts),
  HTTP User-Agent and request-URI extraction with non-browser-UA and C2-style
  URI flags, DNS-tunnelling detection (many long subdomains under one parent),
  and basic PCAPNG parsing (Section/Interface/Enhanced-Packet blocks) instead
  of skipping the format entirely.

## [1.20.0]

### Added
- **Email analyzer depth** (module improvement pass 9): body/phishing analysis -
  hyperlink display-text vs href domain mismatch (the core phishing tell),
  IP-literal-host links, IDN/punycode homograph URLs, URL shorteners,
  suspicious-TLD links, display-name domain spoofing, archive-attachment
  flagging, and body URL/IOC recovery.

## [1.19.0]

### Added
- **Archive analyzer depth** (module improvement pass 8): Unicode RTL/bidi-
  override filename spoofing detection, Zip-Slip path-traversal member names,
  and a dedicated flag for the malspam wrapper shape (archive whose only
  content is a single executable/script).

## [1.18.0]

### Added
- **Android analyzer depth** (module improvement pass 7): APK packer/protector
  detection (Jiagu, Bangcle, DexProtector, Ijiami, Tencent Legu, etc.), native-
  library/ABI reporting, second-stage payload detection (DEX/APK/JAR or
  disguised archive in assets/res), C2 URL recovery from the DEX string pool,
  and expanded suspicious-API coverage (MediaProjection screen capture,
  AudioRecord, accessibility auto-click, application overlay, WebView JS
  bridge, emulator/debugger detection, DownloadManager, crypto).

## [1.17.0]

### Added
- **.NET analyzer depth** (module improvement pass 6): from the recovered CLR
  symbol heap - obfuscator/protector fingerprinting (ConfuserEx, SmartAssembly,
  Eazfuscator, Dotfuscator, .NET Reactor, Babel, etc.), managed->native
  process-injection P/Invoke detection (>=2 native APIs, ATT&CK T1055),
  embedded PowerShell host (System.Management.Automation, T1059.001), dynamic
  native call via delegate (T1620), and symmetric-crypto API use. FP-tuned
  against 120 real framework assemblies.

## [1.16.0]

### Added
- **Mach-O analyzer depth** (module improvement pass 5): real load-command
  parsing - structural code-signature detection, encrypted segment
  (LC_ENCRYPTION_INFO cryptid), RWX segments, linked dylibs and dylib loads
  from world-writable/temp paths (dylib hijacking).

### Fixed
- Mach-O magic endianness mapping was inverted (only affected the byte-swapped
  forms); corrected so load-command parsing reads the right byte order.

## [1.15.0]

### Added
- **PDF analyzer depth** (module improvement pass 4): extracts JavaScript
  from literal /JS strings and FlateDecode-compressed streams, deobfuscates
  it and recovers C2/payload URLs as IOCs; maps known PDF-exploit JS APIs to
  CVEs (util.printf/CVE-2008-2992, Collab.getIcon/CVE-2009-0927, media.
  newPlayer/CVE-2009-4324, collectEmailInfo/CVE-2007-5659, etc.); heap-spray
  shellcode heuristic; /Launch target and /URI IOC extraction; OpenAction+JS
  auto-execution combo; /Encrypt and /XFA detection.

## [1.14.0]

### Added
- **ELF analyzer depth** (module improvement pass 3): real program- and
  section-header parsing (stdlib). Detects RWX (self-modifying) LOAD
  segments, executable stack (NX disabled), absent section headers (UPX/
  packer hallmark), statically linked executables, stripped binaries, and an
  unusual dynamic-linker/interpreter path. Added UPX! artifact, systemd and
  SSH authorized_keys persistence/credential string heuristics.

## [1.13.0]

### Added
- **Office/maldoc analyzer depth** (module improvement pass 2): OOXML
  structural analysis with no macro source needed - remote template injection
  (T1221), external OLE-object relationships, DDE/DDEAUTO field execution
  (T1559.002), Excel 4.0/XLM macro sheets, and embedded OLE objects (payload
  detection). Richer VBA analysis via olevba analyze_macros (auto-exec /
  suspicious / IOC / obfuscation categories), VBA stomping detection
  (T1564.007), and recovered macro IOCs. OLE Ole10Native embedded-filename
  extraction. Relationship Type filtering keeps benign hyperlinks from
  false-positiving.

## [1.12.0]

### Added
- **PE analyzer depth** (module improvement pass 1): rich-header hash
  (richhash) for sample clustering; entry-point anomaly checks (zero EP, EP
  outside all sections, EP in a writable or final section); PE checksum
  validation; compile-timestamp sanity (zeroed / future-forged, REPRO-aware);
  non-standard section-name detection; dynamic-API-resolution-only import
  detection; manifest requestedExecutionLevel (elevation intent); debug PDB
  path extraction (attribution IOC); and high-entropy resource detection
  (media-magic aware to avoid icon/image false positives).

## [1.11.0]

### Added
- **Deep script analyzer**: deobfuscates PowerShell (-EncodedCommand,
  FromBase64String, [char]-code joins), JS/VBS, then matches an original
  ATT&CK-mapped behaviour database (download cradles, dynamic exec,
  AMSI/ETW/Defender evasion, persistence, process injection, credential
  access, discovery, anti-analysis). Emits a kill-chain "behaviour chain"
  finding and recovers embedded C2 IOCs.
- **Stronger deobfuscation engine**: Dean-Edwards eval() packer unrolling,
  obfuscator.io string-array decode (non-rotated), fromCharCode with hex and
  integer arithmetic, and single eval('literal') wrapper peeling.

## [1.10.0]

### Added
- **Deeper macOS analysis**: Mach-O analyzer now flags privilege escalation
  (AuthorizationExecuteWithPrivileges/STPrivilegedTask), credential access
  (keychain, SSH keys), Gatekeeper/SIP disable, TCC access and dylib injection.
- **Android family classification**: heuristically labels APK/DEX samples
  (banking trojan, SMS/OTP stealer, ransomware/locker, RAT/dropper, spyware)
  from the behaviours detected.

## [1.9.0]

### Added
- **Go build-info recovery**: for Go-compiled binaries, recovers the Go
  version, module path and dependency list from the embedded build info
  (great for attribution). Original parser from the public Go format.

## [1.8.0]

### Added (skill-driven: YARA-rule-development + IOC-extraction)
- **More IOC extraction**: mutex names, User-Agent strings, and PDB paths
  (attribution) are now pulled from samples alongside URLs/IPs.
- **STIX 2.1 export** (`--stix FILE`): writes File + Indicator objects (file
  hash, URLs, IPs, recovered C2) for sharing into a TIP/SIEM. Stdlib only.
- **YARA rule-authoring assistant** (`tools/yara_assist.py`): generates a draft
  rule (candidate strings/imports/hex, metadata, filesize guard) from a sample,
  per the rule-development methodology.

## [1.7.0]

### Added
- **JavaScript / script deobfuscation**: unrolls common obfuscation
  (`String.fromCharCode`, `\xNN` / `\uNNNN` escapes, `unescape('%NN')`, string
  concatenation), re-scans the decoded result, and **surfaces the recovered IOCs
  (C2 URLs / IPs)** in the finding - turning "this is an obfuscated dropper" into
  "here is the URL it contacts". Each transform is gated on its trigger so normal
  text is not mangled.

## [1.6.1]

### Fixed
- **Real-world false negative**: an obfuscated JavaScript dropper named `.exe`
  was misclassified as opaque "data" and scored Clean (the script analyzer never
  ran). Fixes:
  - Content-sniff scripts without a script extension (var/function/eval/<?php/
    WScript/powershell/<script), so script droppers under any extension are
    routed to the script analyzer.
  - Any executable extension (.exe/.dll/.scr/.com/...) whose content is not a
    real native binary is now flagged as masquerading (was excluded for
    text/data content).
  - Added a large-obfuscated-script heuristic (big, high-entropy, low-whitespace
    body) for multi-megabyte JS droppers.

## [1.6.0]

### Added
- **Runtime behaviour to MITRE ATT&CK mapping**: dynamic analysis now categorises
  the API calls it observes into capabilities and ATT&CK techniques (and folds
  them into the result's ATT&CK map), so behaviour seen only at runtime - e.g.
  after a packer unpacks in memory - produces the same explainable profile as
  static analysis, with combination logic (injection triad, etc.).
- **Expanded Frida hook set**: ~35 high-signal APIs across process/injection/
  memory, module loading, file, registry/persistence, privilege/credential,
  network and crypto/anti-analysis (was ~13).

Note: live dynamic execution must be validated in a disposable VM
(HAWK_MALWARE_SCAN_SANDBOX=1 + --detonate); the runtime-to-ATT&CK mapping is unit-tested,
the hooking itself is exercised in the VM.

## [1.5.0]

### Added
- **XOR / multi-layer deobfuscation**: brute single-byte XOR keys against known
  plaintext markers (DOS stub, powershell, http, CreateProcess) and re-scan the
  decoded payload, catching XOR-encoded PEs/scripts hidden in any carrier.
  Also runs on base64-decoded blobs (multi-layer). Cost-bounded and false-
  positive-safe (only fires on a marker hit for a non-zero key).

## [1.4.1]

### Fixed
- **False-positive reduction** from a 513-file clean-corpus sweep (7.8% -> 0.8%
  on known-good files), with all true positives preserved:
  - ETW-patch rule now requires a combined AMSI-bypass / memory-patching context
    (ETW APIs alone are common in legitimate binaries).
  - TLS-callback finding downgraded to informational (common in CRT binaries).
  - Linux download-pipe and reverse-shell rules no longer match Windows PEs;
    reverse-shell requires an actual shell-invocation string.
  - Keylogger rule requires keystroke-log formatting strings, not just capture
    APIs (common in GUI apps).
  - Generic eval()/Execute() downgraded to low (legitimate in e.g. Python
    stdlib); PowerShell/WScript download-and-run primitives stay high.
  - Token-impersonation capability downgraded to low (common in legit services).

## [1.4.0]

### Added
- **Attack-technique rule pack** (`hawk-malware-scan_attack.yar`): exploitation strings
  (Log4Shell, ProxyShell/ProxyLogon, Spring4Shell, PrintNightmare), extended
  living-off-the-land binary abuse, credential access (SAM/NTDS dump, vault,
  LaZagne), defense evasion / anti-forensics (event-log clearing, AV/firewall
  disable, timestomp), discovery/recon, and webshell-manager artefacts.
- Bundled rule set now 77 rules across 11 packs.

## [1.3.0]

### Added
- **PDF stream decompression**: FlateDecode object streams are decompressed and
  inspected, catching JavaScript / embedded executables hidden in compressed
  streams (invisible to raw-keyword scanning).
- **Recursive archive scanning**: ZIP members are extracted and re-scanned, so a
  malicious file packed inside an archive is analysed on its own (bounded;
  encrypted/oversized members and zip bombs are skipped).

### Fixed
- **Document/data over-flagging**: non-executable formats (.md, .txt, .log,
  .json, .yaml, config, etc.) no longer produce a heuristic verdict above Low
  Risk - keyword/IOC hits in docs, detection rules and logs are descriptive, not
  behavioural. A CRITICAL hit still escalates.

## [1.2.0]

### Added
- **DLL export analysis**: flags reflective-loader exports (reflective DLL
  injection), regsvr32-loadable COM entry points, tiny generic-name export
  tables (loader/beacon trait), and fully-forwarding DLLs (proxying/hijack).

### Fixed
- **False positives on validly-signed system binaries** (e.g. kernel32):
  - A valid Authenticode/catalog signature now caps a heuristic-only verdict to
    Low Risk (known-bad signals and CRITICAL findings still escalate).
  - Removed the redundant single-API-name string patterns (e.g. a lone
    "VirtualAlloc") that false-positived on DLLs exporting those names; API
    capabilities are scored by the capability analyzer with combination logic.

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
- Tunable configuration via `hawk-malware-scan.toml` / `~/.hawk-malware-scan/config.toml`
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
  function from the reference tool's flag set; Hawk Malware Scan now covers them all.

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
- Offline known-bad **hash denylist** (`~/.hawk-malware-scan/denylist.txt`) that forces a
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
