"""Tests for RTF analysis, binary runtime profiling, and IOC whitelisting."""

from __future__ import annotations

from hawkscan.core import fileinfo
from hawkscan.analyzers.base import AnalysisContext
from hawkscan.analyzers.rtf_analyzer import RTFAnalyzer
from hawkscan.analyzers.binprofile import BinProfileAnalyzer
from hawkscan.analyzers.strings_analyzer import _is_whitelisted


def _ctx(tmp_path, name, data, strings=None):
    f = tmp_path / name
    f.write_bytes(data)
    ctx = AnalysisContext(info=fileinfo.inspect(f), content=data)
    if strings is not None:
        ctx.cache["strings"] = strings
    return ctx


def test_rtf_detected_and_equation_exploit_flagged(tmp_path):
    rtf = (rb"{\rtf1\ansi{\object\objemb\objupdate"
           rb"{\*\objclass Equation.3}{\*\objdata 0105" + b"41" * 512 + rb"}}}")
    ctx = _ctx(tmp_path, "x.rtf", rtf)
    assert ctx.info.file_type == "rtf"
    titles = [f.title for f in RTFAnalyzer().analyze(ctx)]
    assert any("Equation Editor" in t for t in titles)
    assert any("objupdate" in t for t in titles)


def test_binprofile_detects_go(tmp_path):
    ctx = _ctx(tmp_path, "g.exe", b"MZ" + b"\x00" * 64,
               strings=["Go build ID: abc", "go1.21", "runtime.goexit"])
    labels = [f.data.get("runtime") for f in BinProfileAnalyzer().analyze(ctx)]
    assert "Go" in labels


def test_binprofile_detects_dotnet(tmp_path):
    ctx = _ctx(tmp_path, "n.exe", b"MZ" + b"\x00" * 64,
               strings=["mscoree.dll", "_CorExeMain", "mscorlib"])
    labels = [f.data.get("runtime") for f in BinProfileAnalyzer().analyze(ctx)]
    assert ".NET / managed" in labels


def test_onenote_detected_with_embedded_object(tmp_path):
    from hawkscan.analyzers.office_analyzer import OfficeAnalyzer
    one = (b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
           + b"\x00" * 32 + b"\xe7\x16\xe3\xbd\x65\x26\x11\x45" + b"MZ")
    ctx = _ctx(tmp_path, "n.one", one)
    assert ctx.info.file_type == "onenote"
    titles = [f.title for f in OfficeAnalyzer().analyze(ctx)]
    assert any("OneNote embedded file" in t for t in titles)


def test_secrets_and_cloud_detection(tmp_path):
    from hawkscan.analyzers.secrets_analyzer import SecretsAnalyzer
    data = (b"export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            b"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/r\n"
            b"-----BEGIN RSA PRIVATE KEY-----\n")
    ctx = _ctx(tmp_path, "c.sh", data)
    titles = [f.title for f in SecretsAnalyzer().analyze(ctx)]
    assert any("AWS access key" in t for t in titles)
    assert any("IMDS" in t for t in titles)
    assert any("private key" in t.lower() for t in titles)


def test_ios_ipa_type_detection(tmp_path):
    import zipfile
    f = tmp_path / "app.ipa"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", b"<plist></plist>")
    assert fileinfo.inspect(f).file_type == "ios-app"


def test_lnk_command_detection(tmp_path):
    import struct
    from hawkscan.analyzers.lnk_analyzer import LnkAnalyzer
    hdr = bytearray(76)
    hdr[0:4] = (76).to_bytes(4, "little")
    hdr[4:20] = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
    struct.pack_into("<I", hdr, 20, 0x20)
    data = bytes(hdr) + b"powershell -w hidden -enc AAAA http://evil/x"
    ctx = _ctx(tmp_path, "x.lnk", data)
    assert ctx.info.file_type == "lnk"
    titles = [f.title for f in LnkAnalyzer().analyze(ctx)]
    assert any("command interpreter" in t for t in titles)


def test_vbe_encoder_detection(tmp_path):
    from hawkscan.analyzers.script_analyzer import ScriptAnalyzer
    ctx = _ctx(tmp_path, "x.vbe", b"#@~^ABCD==encoded==^#~@")
    titles = [f.title for f in ScriptAnalyzer().analyze(ctx)]
    assert any("Encoded script" in t for t in titles)


def test_pcap_beaconing_detection(tmp_path):
    import struct
    from hawkscan.analyzers.pcap_analyzer import PcapAnalyzer

    def rec(ts):
        eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 5]), bytes([45, 77, 88, 99]))
        tcp = struct.pack(">HHIIBBHHH", 44000, 443, 0, 0, 0x50, 2, 0, 0, 0)
        pkt = eth + ip + tcp
        return struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt

    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    body = b"".join(rec(1000 + i * 10) for i in range(10))
    ctx = _ctx(tmp_path, "b.pcap", gh + body)
    titles = [f.title for f in PcapAnalyzer().analyze(ctx)]
    assert any("Beaconing" in t for t in titles)


def test_stego_appended_executable(tmp_path):
    from hawkscan.analyzers.stego_analyzer import StegoAnalyzer
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 200 + b"\xff\xd9"
    ctx = _ctx(tmp_path, "s.jpg", jpeg + b"MZ\x90\x00" + b"\x00" * 300)
    titles = [f.title for f in StegoAnalyzer().analyze(ctx)]
    assert any("appended after image" in t for t in titles)


def test_polyglot_detection(tmp_path):
    from hawkscan.analyzers.stego_analyzer import StegoAnalyzer
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40 + b"IEND" + b"\x00" * 4
    ctx = _ctx(tmp_path, "p.png", png + b"PK\x03\x04 zip")
    titles = [f.title for f in StegoAnalyzer().analyze(ctx)]
    assert any("Polyglot" in t for t in titles)


def test_ole_analyzer_handles_non_ole_gracefully(tmp_path):
    from hawkscan.analyzers.ole_analyzer import OleAnalyzer
    # Applies only to OLE; a non-OLE file simply does not match.
    ctx = _ctx(tmp_path, "x.txt", b"not an ole file")
    assert OleAnalyzer().applies(ctx) is False


def test_ioc_whitelist():
    assert _is_whitelisted("http://schemas.microsoft.com/office")
    assert _is_whitelisted("http://www.w3.org/2000/svg")
    assert not _is_whitelisted("http://evil-c2-domain.tk/payload")


def test_pcap_extracts_dns_and_flags_suspicious_tld(tmp_path):
    import struct
    from hawkscan.analyzers.pcap_analyzer import PcapAnalyzer

    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for lbl in "evil-c2.ru".split("."):
        dns += bytes([len(lbl)]) + lbl.encode()
    dns += b"\x00" + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 5000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 5]), bytes([45, 77, 88, 99]))
    pkt = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + udp
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt

    ctx = _ctx(tmp_path, "t.pcap", gh + rec)
    assert ctx.info.file_type == "pcap"
    findings = list(PcapAnalyzer().analyze(ctx))
    titles = [f.title for f in findings]
    assert any("DNS quer" in t for t in titles)
    assert any("suspicious-TLD" in t for t in titles)


def test_email_phishing_indicators(tmp_path):
    import base64
    from hawkscan.analyzers.email_analyzer import EmailAnalyzer
    pe_b64 = base64.b64encode(b"MZ" + b"\x90" * 32).decode()
    eml = (
        'From: "Bank" <help@bank.com>\n'
        "Return-Path: <attacker@evil.ru>\n"
        "MIME-Version: 1.0\n"
        "Authentication-Results: mx; spf=fail; dmarc=fail\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nopen it\n"
        "--B\nContent-Type: application/octet-stream; name=\"doc.pdf.exe\"\n"
        "Content-Transfer-Encoding: base64\n"
        'Content-Disposition: attachment; filename="doc.pdf.exe"\n\n'
        f"{pe_b64}\n--B--\n"
    ).encode()
    ctx = _ctx(tmp_path, "p.eml", eml)
    assert ctx.info.file_type == "email"
    titles = [f.title for f in EmailAnalyzer().analyze(ctx)]
    assert any("SPF" in t for t in titles)
    assert any("Double-extension" in t for t in titles)
    assert any("Return-Path" in t for t in titles)
