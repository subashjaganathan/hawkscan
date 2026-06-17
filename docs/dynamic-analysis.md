# Dynamic analysis: safe setup

HawkScan is static by default and never executes a file. The optional dynamic
module *runs* the sample to observe its behaviour, which is dangerous. Read this
before using it.

## Golden rule

Only ever run dynamic analysis inside a disposable, snapshotted virtual machine
with controlled networking. Never on your workstation or any machine with data
you care about.

HawkScan enforces this with a hard gate: dynamic analysis refuses to run unless
the environment variable `HAWKSCAN_SANDBOX=1` is set. Set it only inside the
analysis VM.

## Recommended VM setup

1. Create a VM (VirtualBox/VMware/Hyper-V) matching the sample's OS.
2. Take a clean snapshot before any analysis. Revert to it after every sample.
3. Network: isolate it. Use a host-only network, an INetSim/FakeNet style
   internet simulator, or no network at all. Do not bridge it to your LAN.
4. Install HawkScan and the optional tools you need:
   ```bash
   pip install -e ".[dynamic]"   # psutil + frida
   # plus, per tracer: strace (Linux), adb + an emulator (Android)
   ```
5. Mark the VM as a sandbox:
   ```bash
   export HAWKSCAN_SANDBOX=1      # Windows: setx HAWKSCAN_SANDBOX 1
   ```

## Running it

Both `--dynamic` and `--detonate` are required to actually execute a sample:

```bash
hawkscan sample.exe --dynamic --detonate --dynamic-timeout 30
```

Select a tracer with `--dynamic-method`:

| Method | What it captures | Needs |
|--------|------------------|-------|
| `auto` (default) | best available for the file/platform | - |
| `monitor` | child processes, dropped files, network | psutil (optional) |
| `strace` | Linux syscalls (file/network/process) | Linux + strace |
| `frida` | API calls (process/injection/network/registry/crypto) | frida |
| `adb` | Android logcat behaviour after install/launch | adb + emulator |

The process tree is killed when the timeout elapses, and the sample runs in a
temporary working directory that is removed afterwards.

## After each run

Revert the VM to its clean snapshot. Behavioural artefacts (dropped files,
persistence, injected processes) may persist otherwise and contaminate the next
analysis.
