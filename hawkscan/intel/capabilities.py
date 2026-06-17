"""API-name to capability category and MITRE ATT&CK technique mapping.

This is the knowledge base behind HawkScan's capability analysis: given the
function/API names a binary imports or references, it groups them into
behavioural categories (Networking, Process Injection, Keylogging, ...) and the
MITRE ATT&CK techniques those categories represent.

Names are matched case-insensitively, and trailing A/W/Ex variants are folded,
so VirtualAllocEx, WriteProcessMemory, RegSetValueExA, etc. all resolve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Relative risk weight of each capability category. The capability analyzer
# turns these into finding severities, so tune detection sensitivity here.
CATEGORY_SEVERITY: dict[str, str] = {
    "Process Injection": "high",
    "Keylogging / Input Capture": "high",
    "Anti-Debug / Anti-Analysis": "medium",
    "Anti-VM / Sandbox Evasion": "medium",
    "Persistence": "medium",
    "Privilege Escalation": "medium",
    "Cryptography / Ransomware": "medium",
    "Credential Access": "high",
    "Code Execution": "low",
    "Process / Thread Manipulation": "low",
    "Networking": "low",
    "Registry": "low",
    "File System": "info",
    "Service Manipulation": "low",
    "System Discovery": "low",
    "Screen / Audio Capture": "medium",
    "Dynamic API Resolution": "medium",
}

# (category, mitre_id, mitre_name). mitre_id may be "" when no clean mapping.
_T = lambda c, i, n: (c, i, n)  # noqa: E731 (compact table builder)

API_DB: dict[str, tuple[str, str, str]] = {
    # --- Process injection (T1055) ---
    "VirtualAllocEx": _T("Process Injection", "T1055", "Process Injection"),
    "VirtualAlloc": _T("Process Injection", "T1055", "Process Injection"),
    "WriteProcessMemory": _T("Process Injection", "T1055", "Process Injection"),
    "CreateRemoteThread": _T("Process Injection", "T1055.002", "Portable Executable Injection"),
    "NtCreateThreadEx": _T("Process Injection", "T1055", "Process Injection"),
    "RtlCreateUserThread": _T("Process Injection", "T1055", "Process Injection"),
    "NtUnmapViewOfSection": _T("Process Injection", "T1055.012", "Process Hollowing"),
    "ZwUnmapViewOfSection": _T("Process Injection", "T1055.012", "Process Hollowing"),
    "QueueUserAPC": _T("Process Injection", "T1055.004", "Asynchronous Procedure Call"),
    "SetThreadContext": _T("Process Injection", "T1055.012", "Process Hollowing"),
    "MapViewOfFile": _T("Process Injection", "T1055", "Process Injection"),
    "VirtualProtect": _T("Process Injection", "T1055", "Process Injection"),

    # --- Code execution (T1106 / T1059) ---
    "WinExec": _T("Code Execution", "T1106", "Native API"),
    "ShellExecuteA": _T("Code Execution", "T1059", "Command and Scripting Interpreter"),
    "ShellExecuteW": _T("Code Execution", "T1059", "Command and Scripting Interpreter"),
    "ShellExecuteExW": _T("Code Execution", "T1059", "Command and Scripting Interpreter"),
    "CreateProcessA": _T("Code Execution", "T1106", "Native API"),
    "CreateProcessW": _T("Code Execution", "T1106", "Native API"),
    "CreateProcessInternalW": _T("Code Execution", "T1106", "Native API"),
    "system": _T("Code Execution", "T1059", "Command and Scripting Interpreter"),
    "execve": _T("Code Execution", "T1059.004", "Unix Shell"),
    "popen": _T("Code Execution", "T1059", "Command and Scripting Interpreter"),
    "fork": _T("Code Execution", "T1106", "Native API"),

    # --- Dynamic API resolution (T1027 / T1106) ---
    "GetProcAddress": _T("Dynamic API Resolution", "T1106", "Native API"),
    "LoadLibraryA": _T("Dynamic API Resolution", "T1129", "Shared Modules"),
    "LoadLibraryW": _T("Dynamic API Resolution", "T1129", "Shared Modules"),
    "LdrLoadDll": _T("Dynamic API Resolution", "T1129", "Shared Modules"),
    "LdrGetProcedureAddress": _T("Dynamic API Resolution", "T1106", "Native API"),
    "dlopen": _T("Dynamic API Resolution", "T1129", "Shared Modules"),
    "dlsym": _T("Dynamic API Resolution", "T1106", "Native API"),

    # --- Networking (T1071 / T1095) ---
    "socket": _T("Networking", "T1095", "Non-Application Layer Protocol"),
    "connect": _T("Networking", "T1071", "Application Layer Protocol"),
    "send": _T("Networking", "T1071", "Application Layer Protocol"),
    "recv": _T("Networking", "T1071", "Application Layer Protocol"),
    "WSAStartup": _T("Networking", "T1071", "Application Layer Protocol"),
    "WSASocketA": _T("Networking", "T1095", "Non-Application Layer Protocol"),
    "InternetOpenA": _T("Networking", "T1071.001", "Web Protocols"),
    "InternetOpenW": _T("Networking", "T1071.001", "Web Protocols"),
    "InternetOpenUrlA": _T("Networking", "T1071.001", "Web Protocols"),
    "InternetConnectA": _T("Networking", "T1071.001", "Web Protocols"),
    "InternetReadFile": _T("Networking", "T1071.001", "Web Protocols"),
    "HttpSendRequestA": _T("Networking", "T1071.001", "Web Protocols"),
    "HttpOpenRequestA": _T("Networking", "T1071.001", "Web Protocols"),
    "URLDownloadToFileA": _T("Networking", "T1105", "Ingress Tool Transfer"),
    "URLDownloadToFileW": _T("Networking", "T1105", "Ingress Tool Transfer"),
    "WinHttpOpen": _T("Networking", "T1071.001", "Web Protocols"),
    "WinHttpConnect": _T("Networking", "T1071.001", "Web Protocols"),
    "gethostbyname": _T("Networking", "T1071", "Application Layer Protocol"),
    "getaddrinfo": _T("Networking", "T1071", "Application Layer Protocol"),

    # --- Keylogging / input capture (T1056.001) ---
    "GetAsyncKeyState": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),
    "GetKeyState": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),
    "GetKeyboardState": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),
    "SetWindowsHookExA": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),
    "SetWindowsHookExW": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),
    "RegisterRawInputDevices": _T("Keylogging / Input Capture", "T1056.001", "Keylogging"),

    # --- Screen / audio capture (T1113 / T1123) ---
    "BitBlt": _T("Screen / Audio Capture", "T1113", "Screen Capture"),
    "GetDC": _T("Screen / Audio Capture", "T1113", "Screen Capture"),
    "CreateCompatibleBitmap": _T("Screen / Audio Capture", "T1113", "Screen Capture"),
    "waveInOpen": _T("Screen / Audio Capture", "T1123", "Audio Capture"),

    # --- Anti-debug / anti-analysis (T1622 / T1497) ---
    "IsDebuggerPresent": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "CheckRemoteDebuggerPresent": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "NtQueryInformationProcess": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "OutputDebugStringA": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "ptrace": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "GetTickCount": _T("Anti-Debug / Anti-Analysis", "T1497", "Virtualization/Sandbox Evasion"),
    "QueryPerformanceCounter": _T("Anti-Debug / Anti-Analysis", "T1497", "Virtualization/Sandbox Evasion"),

    # --- Anti-VM / sandbox evasion (T1497) ---
    "GetSystemFirmwareTable": _T("Anti-VM / Sandbox Evasion", "T1497.001", "System Checks"),
    "cpuid": _T("Anti-VM / Sandbox Evasion", "T1497.001", "System Checks"),
    "GetModuleHandleA": _T("Anti-VM / Sandbox Evasion", "T1497", "Virtualization/Sandbox Evasion"),

    # --- Persistence (T1547 / T1543) ---
    "RegSetValueExA": _T("Persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "RegSetValueExW": _T("Persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "RegCreateKeyExA": _T("Persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "CreateServiceA": _T("Persistence", "T1543.003", "Windows Service"),
    "CreateServiceW": _T("Persistence", "T1543.003", "Windows Service"),
    "OpenSCManagerA": _T("Service Manipulation", "T1543.003", "Windows Service"),
    "StartServiceA": _T("Service Manipulation", "T1543.003", "Windows Service"),
    "schtasks": _T("Persistence", "T1053.005", "Scheduled Task"),

    # --- Registry (T1112) ---
    "RegOpenKeyExA": _T("Registry", "T1112", "Modify Registry"),
    "RegQueryValueExA": _T("Registry", "T1012", "Query Registry"),
    "RegDeleteValueA": _T("Registry", "T1112", "Modify Registry"),

    # --- Cryptography / ransomware (T1486) ---
    "CryptEncrypt": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),
    "CryptDecrypt": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),
    "CryptAcquireContextA": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),
    "CryptGenKey": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),
    "BCryptEncrypt": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),
    "EVP_EncryptInit": _T("Cryptography / Ransomware", "T1486", "Data Encrypted for Impact"),

    # --- Credential access (T1003 / T1555) ---
    "LsaRetrievePrivateData": _T("Credential Access", "T1003", "OS Credential Dumping"),
    "CredEnumerateA": _T("Credential Access", "T1555", "Credentials from Password Stores"),
    "MiniDumpWriteDump": _T("Credential Access", "T1003.001", "LSASS Memory"),
    "SamConnect": _T("Credential Access", "T1003.002", "Security Account Manager"),

    # --- Privilege escalation (T1134 / T1548) ---
    "AdjustTokenPrivileges": _T("Privilege Escalation", "T1134.001", "Token Impersonation/Theft"),
    "OpenProcessToken": _T("Privilege Escalation", "T1134", "Access Token Manipulation"),
    "DuplicateTokenEx": _T("Privilege Escalation", "T1134.001", "Token Impersonation/Theft"),
    "ImpersonateLoggedOnUser": _T("Privilege Escalation", "T1134.001", "Token Impersonation/Theft"),
    "setuid": _T("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),

    # --- Process / thread manipulation & discovery (T1057 / T1082) ---
    "OpenProcess": _T("Process / Thread Manipulation", "T1057", "Process Discovery"),
    "CreateToolhelp32Snapshot": _T("System Discovery", "T1057", "Process Discovery"),
    "Process32First": _T("System Discovery", "T1057", "Process Discovery"),
    "Process32Next": _T("System Discovery", "T1057", "Process Discovery"),
    "EnumProcesses": _T("System Discovery", "T1057", "Process Discovery"),
    "GetComputerNameA": _T("System Discovery", "T1082", "System Information Discovery"),
    "GetSystemInfo": _T("System Discovery", "T1082", "System Information Discovery"),
    "GetUserNameA": _T("System Discovery", "T1033", "System Owner/User Discovery"),
    "GetVolumeInformationA": _T("System Discovery", "T1082", "System Information Discovery"),

    # --- File system (often benign; informational) ---
    "CreateFileA": _T("File System", "", ""),
    "CreateFileW": _T("File System", "", ""),
    "WriteFile": _T("File System", "", ""),
    "ReadFile": _T("File System", "", ""),
    "DeleteFileA": _T("File System", "T1070.004", "File Deletion"),
    "MoveFileExA": _T("File System", "", ""),
    "FindFirstFileA": _T("File System", "T1083", "File and Directory Discovery"),
    "FindNextFileA": _T("File System", "T1083", "File and Directory Discovery"),
    "SetFileAttributesA": _T("File System", "T1564.001", "Hidden Files and Directories"),

    # --- Additional injection / memory primitives ---
    "NtWriteVirtualMemory": _T("Process Injection", "T1055", "Process Injection"),
    "NtMapViewOfSection": _T("Process Injection", "T1055", "Process Injection"),
    "NtProtectVirtualMemory": _T("Process Injection", "T1055", "Process Injection"),
    "NtQueueApcThread": _T("Process Injection", "T1055.004", "Asynchronous Procedure Call"),
    "GlobalAddAtomA": _T("Process Injection", "T1055.014", "Atom Bombing"),
    "ResumeThread": _T("Process / Thread Manipulation", "T1055.012", "Process Hollowing"),

    # --- Additional networking ---
    "HttpSendRequestW": _T("Networking", "T1071.001", "Web Protocols"),
    "WSAConnect": _T("Networking", "T1095", "Non-Application Layer Protocol"),
    "DnsQuery_A": _T("Networking", "T1071.004", "DNS"),
    "InternetSetOptionA": _T("Networking", "T1071.001", "Web Protocols"),
    "WSASend": _T("Networking", "T1071", "Application Layer Protocol"),

    # --- Defense evasion ---
    "RtlAddVectoredExceptionHandler": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "GetThreadContext": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "NtSetInformationThread": _T("Anti-Debug / Anti-Analysis", "T1622", "Debugger Evasion"),
    "BlockInput": _T("Anti-Debug / Anti-Analysis", "T1497", "Virtualization/Sandbox Evasion"),
    "EnumDeviceDrivers": _T("Anti-VM / Sandbox Evasion", "T1497.001", "System Checks"),

    # --- Discovery ---
    "GetAdaptersInfo": _T("System Discovery", "T1016", "System Network Configuration Discovery"),
    "NetUserEnum": _T("System Discovery", "T1087", "Account Discovery"),
    "RegEnumKeyExA": _T("Registry", "T1012", "Query Registry"),
    "GetForegroundWindow": _T("System Discovery", "T1010", "Application Window Discovery"),
    "GetNativeSystemInfo": _T("System Discovery", "T1082", "System Information Discovery"),

    # --- Privilege escalation / credential ---
    "LookupPrivilegeValueA": _T("Privilege Escalation", "T1134", "Access Token Manipulation"),
    "CreateProcessAsUserA": _T("Privilege Escalation", "T1134.002", "Create Process with Token"),
    "CredReadA": _T("Credential Access", "T1555", "Credentials from Password Stores"),
    "LsaEnumerateLogonSessions": _T("Credential Access", "T1003", "OS Credential Dumping"),

    # --- Service manipulation ---
    "ChangeServiceConfig2A": _T("Service Manipulation", "T1543.003", "Windows Service"),
    "ControlService": _T("Service Manipulation", "T1543.003", "Windows Service"),
}

# Normalised lookup (lowercased, A/W/Ex suffixes folded).
def _normalize(name: str) -> str:
    n = name.strip().lower()
    for suffix in ("exa", "exw", "ex", "a", "w"):
        if n.endswith(suffix) and len(n) > len(suffix) + 2:
            base = n[: -len(suffix)]
            if base in _NORM_INDEX:
                return base
    return n


_NORM_INDEX: dict[str, str] = {k.lower(): k for k in API_DB}
# Also index suffix-folded forms so connect/connectA both resolve.
for _k in list(API_DB):
    _base = _k.lower()
    for _suf in ("ExA", "ExW", "Ex", "A", "W"):
        if _base.endswith(_suf.lower()):
            _NORM_INDEX.setdefault(_base[: -len(_suf)], _k)


@dataclass
class Capability:
    category: str
    apis: list[str] = field(default_factory=list)
    techniques: dict[str, str] = field(default_factory=dict)  # id -> name


def categorize(names) -> tuple[dict[str, Capability], dict[str, dict]]:
    """Given API/function names, return:
      - capabilities: {category: Capability}
      - techniques:   {mitre_id: {"name": str, "categories": [..], "apis": [..]}}
    """
    caps: dict[str, Capability] = {}
    techs: dict[str, dict] = {}

    for raw in names:
        key = _NORM_INDEX.get(raw.lower()) or _NORM_INDEX.get(_normalize(raw))
        if not key:
            continue
        category, tid, tname = API_DB[key]
        cap = caps.setdefault(category, Capability(category=category))
        if key not in cap.apis:
            cap.apis.append(key)
        if tid:
            cap.techniques[tid] = tname
            t = techs.setdefault(tid, {"name": tname, "categories": [], "apis": []})
            if category not in t["categories"]:
                t["categories"].append(category)
            if key not in t["apis"]:
                t["apis"].append(key)

    for cap in caps.values():
        cap.apis.sort()
    return caps, techs


# Case-sensitive, word-boundary matcher over a blob of strings. Used as a
# fallback for binaries with no readable import table (packed PE, ELF, Mach-O).
# Longest-first so e.g. CreateProcessInternalW wins over CreateProcessW.
_API_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(API_DB, key=len, reverse=True)) + r")\b"
)


def scan_text(blob: str) -> set[str]:
    """Return the set of known API names appearing as tokens in `blob`."""
    return set(_API_PATTERN.findall(blob))


# --- High-confidence API combinations ------------------------------------
# Individual API presence is weak signal (legitimate software uses most of
# these). Real maliciousness shows up in COMBINATIONS that are rarely benign
# together. Only these drive the score; the per-category inventory above is
# purely informational.
@dataclass
class Combo:
    name: str
    any_of: list[str]          # APIs to count
    min_count: int             # how many distinct must be present
    severity: str              # info|low|medium|high|critical
    category: str
    mitre: tuple[str, str]     # (id, name)
    detail: str


COMBINATIONS: list[Combo] = [
    Combo(
        name="Classic process injection",
        any_of=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
                "SetThreadContext", "NtUnmapViewOfSection"],
        min_count=2, severity="high", category="Process Injection",
        mitre=("T1055", "Process Injection"),
        detail="Multiple process-injection primitives present together.",
    ),
    Combo(
        name="Process hollowing",
        any_of=["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
                "WriteProcessMemory"],
        min_count=2, severity="high", category="Process Injection",
        mitre=("T1055.012", "Process Hollowing"),
        detail="Unmap + write/context primitives indicate process hollowing.",
    ),
    Combo(
        name="Keylogging",
        any_of=["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                "GetKeyboardState", "RegisterRawInputDevices"],
        min_count=1, severity="medium", category="Keylogging / Input Capture",
        mitre=("T1056.001", "Keylogging"),
        detail="Keyboard-state / input-hook API present.",
    ),
    Combo(
        name="Credential dumping",
        any_of=["MiniDumpWriteDump", "SamConnect", "LsaRetrievePrivateData"],
        min_count=1, severity="high", category="Credential Access",
        mitre=("T1003", "OS Credential Dumping"),
        detail="Credential-store / LSASS access primitive present.",
    ),
    Combo(
        name="Download and execute",
        any_of=["URLDownloadToFileA", "URLDownloadToFileW", "InternetReadFile",
                "WinHttpConnect"],
        min_count=1, severity="medium", category="Networking",
        mitre=("T1105", "Ingress Tool Transfer"),
        detail="Remote file download primitive (stager/dropper pattern).",
    ),
    Combo(
        name="Token impersonation",
        any_of=["DuplicateTokenEx", "ImpersonateLoggedOnUser",
                "AdjustTokenPrivileges"],
        min_count=2, severity="medium", category="Privilege Escalation",
        mitre=("T1134.001", "Token Impersonation/Theft"),
        detail="Token duplication/impersonation primitives present together.",
    ),
]


def detect_combinations(names) -> list[dict]:
    """Return high-confidence combination hits for a set of API names."""
    present = {n for n in names}
    # Case-insensitive membership for robustness.
    lower = {n.lower() for n in present}

    def has(api: str) -> bool:
        return api in present or api.lower() in lower

    hits: list[dict] = []
    for combo in COMBINATIONS:
        matched = [a for a in combo.any_of if has(a)]
        if len(matched) >= combo.min_count:
            hits.append({
                "name": combo.name, "severity": combo.severity,
                "category": combo.category, "mitre": combo.mitre,
                "apis": matched, "detail": combo.detail,
            })
    return hits
