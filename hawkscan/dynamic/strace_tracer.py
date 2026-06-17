"""Linux dynamic tracing via strace.

Runs a sample under `strace -f` and parses the syscall log into behaviour:
files opened for write, network connects, and processes executed. Requires the
strace binary; returns a skipped result on non-Linux or when strace is absent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

_CONNECT_RE = re.compile(r'connect\(\d+,\s*\{sa_family=AF_INET[^}]*'
                         r'sin_port=htons\((\d+)\)[^}]*inet_addr\("([\d.]+)"\)')
_EXECVE_RE = re.compile(r'execve\("([^"]+)"')
_OPENWR_RE = re.compile(r'openat?\([^,]*,\s*"([^"]+)"[^)]*O_(?:WRONLY|RDWR|CREAT)')


def available() -> bool:
    return shutil.which("strace") is not None


def trace(cmd: list[str], cwd: str, timeout: int) -> dict:
    """Run cmd under strace; return parsed behaviour dict."""
    out = {"files": set(), "network": set(), "processes": set(),
           "syscalls": set(), "timed_out": False, "returncode": None}
    log = Path(tempfile.mktemp(prefix="hawkscan_strace_", suffix=".log"))
    straced = ["strace", "-f", "-qq", "-o", str(log),
               "-e", "trace=network,process,openat,open", *cmd]
    start = time.perf_counter()
    try:
        proc = subprocess.run(straced, cwd=cwd, capture_output=True,
                              timeout=timeout)
        out["returncode"] = proc.returncode
    except subprocess.TimeoutExpired:
        out["timed_out"] = True
    except Exception:
        return out
    finally:
        out["duration_s"] = time.perf_counter() - start

    try:
        text = log.read_text("latin1", errors="ignore")
    except OSError:
        return out
    finally:
        log.unlink(missing_ok=True)

    for line in text.splitlines():
        m = _CONNECT_RE.search(line)
        if m:
            out["network"].add(f"{m.group(2)}:{m.group(1)}")
        m = _EXECVE_RE.search(line)
        if m:
            out["processes"].add(m.group(1))
        m = _OPENWR_RE.search(line)
        if m and not m.group(1).startswith(("/proc", "/sys", "/dev", "/etc/ld")):
            out["files"].add(m.group(1))
        # Keep a deduped sample of interesting syscall names.
        sm = re.match(r"(?:\[pid\s+\d+\]\s*)?(\w+)\(", line)
        if sm and sm.group(1) in {
            "ptrace", "fork", "clone", "execve", "socket", "connect",
            "chmod", "unlink", "mprotect", "mmap"
        }:
            out["syscalls"].add(sm.group(1))

    for k in ("files", "network", "processes", "syscalls"):
        out[k] = sorted(out[k])
    return out
