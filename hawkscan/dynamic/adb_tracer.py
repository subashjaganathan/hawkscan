"""Android dynamic analysis via ADB.

Installs an APK on a connected emulator/device, launches it, captures logcat for
the run window, and extracts behavioural hints (network, telephony, runtime
exec), then uninstalls. Requires the adb binary and a connected device.

Intended for use against a disposable emulator, never a real phone with data.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import zipfile

_PKG_RE = re.compile(r"package:\s*name='([^']+)'")
_LOGCAT_HINTS = [
    (re.compile(r"sendTextMessage|SmsManager", re.I), "telephony", "SMS API used"),
    (re.compile(r"Runtime.*exec|ProcessBuilder", re.I), "execution", "Command execution"),
    (re.compile(r"DexClassLoader|PathClassLoader", re.I), "dynamic-code", "Dynamic code load"),
    (re.compile(r"https?://\S+", re.I), "network", "Network URL contacted"),
    (re.compile(r"getDeviceId|getSubscriberId", re.I), "device-id", "Device identifier read"),
]


def available() -> bool:
    return shutil.which("adb") is not None


def _adb(args: list[str], timeout: int = 30) -> str:
    try:
        p = subprocess.run(["adb", *args], capture_output=True, timeout=timeout)
        return (p.stdout or b"").decode("latin1", "ignore")
    except Exception:
        return ""


def _device_connected() -> bool:
    out = _adb(["devices"])
    return any(line.strip().endswith("device") for line in out.splitlines()[1:])


def _package_name(apk: str) -> str:
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        try:
            p = subprocess.run([aapt, "dump", "badging", apk],
                              capture_output=True, timeout=30)
            m = _PKG_RE.search((p.stdout or b"").decode("latin1", "ignore"))
            if m:
                return m.group(1)
        except Exception:
            pass
    # Fallback: read package from the binary manifest strings in the APK.
    try:
        with zipfile.ZipFile(apk) as zf:
            man = zf.read("AndroidManifest.xml")
        m = re.search(rb"([a-z][a-z0-9_]+(?:\.[a-z][a-z0-9_]+){2,})", man)
        if m:
            return m.group(1).decode("latin1")
    except Exception:
        pass
    return ""


def trace(apk: str, timeout: int) -> dict:
    out = {"package": "", "behaviours": [], "logcat_tail": "", "notes": [],
           "network": []}
    if not available():
        out["notes"].append("adb not installed")
        return out
    if not _device_connected():
        out["notes"].append("no adb device/emulator connected")
        return out

    pkg = _package_name(apk)
    out["package"] = pkg
    if _adb(["install", "-r", apk]).strip().lower().find("success") == -1 and not pkg:
        out["notes"].append("install failed")
        return out

    _adb(["logcat", "-c"])  # clear
    if pkg:
        _adb(["shell", "monkey", "-p", pkg, "-c",
              "android.intent.category.LAUNCHER", "1"])
    time.sleep(min(timeout, 60))
    logs = _adb(["logcat", "-d"])
    out["logcat_tail"] = logs = logs[-4000:]

    seen = set()
    for pattern, cat, desc in _LOGCAT_HINTS:
        if pattern.search(logs) and desc not in seen:
            seen.add(desc)
            out["behaviours"].append({"category": cat, "detail": desc})
    out["network"] = sorted(set(re.findall(r"https?://[^\s\"']+", logs)))[:20]

    if pkg:
        _adb(["uninstall", pkg])
    return out
