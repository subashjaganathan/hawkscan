"""Dynamic API hooking via Frida.

Spawns the sample suspended, injects an instrumentation script that hooks the
APIs malware commonly uses (process creation, injection, networking, registry,
crypto), records the calls, then lets it run for the timeout. Requires the
optional `frida` package and a target platform Frida supports.

The injected script is our own, intentionally small: it traces a fixed set of
high-signal exports and reports each call back to the Python side.
"""

from __future__ import annotations

import time

try:
    import frida  # type: ignore
    _HAVE_FRIDA = True
except Exception:
    _HAVE_FRIDA = False

# Original instrumentation script: attach to a curated set of high-signal APIs
# and post a compact message per call.
_SCRIPT = r"""
const TARGETS = [
  // Process / execution
  ["kernel32.dll", "CreateProcessW", "process"],
  ["kernel32.dll", "CreateProcessInternalW", "process"],
  ["kernel32.dll", "WinExec", "process"],
  ["shell32.dll", "ShellExecuteExW", "process"],
  // Injection / memory
  ["kernel32.dll", "VirtualAllocEx", "injection"],
  ["kernel32.dll", "WriteProcessMemory", "injection"],
  ["kernel32.dll", "CreateRemoteThread", "injection"],
  ["kernel32.dll", "VirtualProtect", "injection"],
  ["ntdll.dll", "NtWriteVirtualMemory", "injection"],
  ["ntdll.dll", "NtCreateThreadEx", "injection"],
  ["ntdll.dll", "NtUnmapViewOfSection", "injection"],
  ["ntdll.dll", "NtMapViewOfSection", "injection"],
  ["ntdll.dll", "QueueUserAPC", "injection"],
  // Dynamic resolution / modules
  ["kernel32.dll", "LoadLibraryW", "module"],
  ["kernel32.dll", "GetProcAddress", "module"],
  ["ntdll.dll", "LdrLoadDll", "module"],
  // File
  ["kernel32.dll", "WriteFile", "file"],
  ["kernel32.dll", "CreateFileW", "file"],
  ["kernel32.dll", "DeleteFileW", "file"],
  // Registry / persistence
  ["advapi32.dll", "RegSetValueExW", "registry"],
  ["advapi32.dll", "RegCreateKeyExW", "registry"],
  ["advapi32.dll", "CreateServiceW", "persistence"],
  ["taskschd.dll", "NewTask", "persistence"],
  // Privilege / credentials
  ["advapi32.dll", "AdjustTokenPrivileges", "privilege"],
  ["advapi32.dll", "OpenProcessToken", "privilege"],
  ["dbghelp.dll", "MiniDumpWriteDump", "credential"],
  // Network
  ["wininet.dll", "InternetOpenUrlW", "network"],
  ["winhttp.dll", "WinHttpConnect", "network"],
  ["ws2_32.dll", "connect", "network"],
  ["ws2_32.dll", "send", "network"],
  ["urlmon.dll", "URLDownloadToFileW", "network"],
  // Crypto / anti-analysis
  ["advapi32.dll", "CryptEncrypt", "crypto"],
  ["bcrypt.dll", "BCryptEncrypt", "crypto"],
  ["kernel32.dll", "IsDebuggerPresent", "anti-analysis"],
  ["ntdll.dll", "NtQueryInformationProcess", "anti-analysis"],
];
TARGETS.forEach(function (t) {
  const mod = t[0], fn = t[1], cat = t[2];
  let addr = null;
  try { addr = Module.getExportByName(mod, fn); } catch (e) { return; }
  try {
    Interceptor.attach(addr, {
      onEnter: function () { send({ api: fn, category: cat }); }
    });
  } catch (e) {}
});
"""


def available() -> bool:
    return _HAVE_FRIDA


def trace(cmd: list[str], timeout: int) -> dict:
    """Spawn cmd under Frida, hook APIs, collect calls. cmd[0] is the target."""
    out = {"api_calls": [], "categories": set(), "timed_out": False,
           "notes": [], "returncode": None}
    if not _HAVE_FRIDA:
        out["notes"].append("frida not installed")
        return out

    calls: dict[str, int] = {}
    cats: set[str] = set()

    def on_message(message, data):
        if message.get("type") == "send":
            p = message.get("payload", {})
            api = p.get("api")
            if api:
                calls[api] = calls.get(api, 0) + 1
                if p.get("category"):
                    cats.add(p["category"])

    try:
        device = frida.get_local_device()
        pid = device.spawn(cmd)
        session = device.attach(pid)
        script = session.create_script(_SCRIPT)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            time.sleep(0.2)
        try:
            device.kill(pid)
        except Exception:
            pass
    except Exception as exc:  # frida raises on unsupported targets/perE
        out["notes"].append(f"frida error: {exc}")
        return out

    out["api_calls"] = sorted(f"{k} x{v}" for k, v in calls.items())
    out["categories"] = sorted(cats)
    return out
