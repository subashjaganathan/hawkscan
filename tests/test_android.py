"""Tests for Android APK / DEX analysis."""

from __future__ import annotations

import zipfile

from hawk_malware_scan.core import fileinfo
from hawk_malware_scan.analyzers.base import AnalysisContext
from hawk_malware_scan.analyzers.android_analyzer import AndroidAnalyzer


def _build_apk(path):
    manifest = ("android.permission.SEND_SMS\n"
                "android.permission.BIND_ACCESSIBILITY_SERVICE\n"
                "android.permission.CAMERA").encode("utf-16-le")
    dex = b"dex\n035\x00" + b"sendTextMessage DexClassLoader getDeviceId lockNow"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
    return path


def test_apk_detection_and_findings(tmp_path):
    apk = _build_apk(tmp_path / "app.apk")
    ctx = AnalysisContext(info=fileinfo.inspect(apk), content=apk.read_bytes())
    assert ctx.info.file_type == "apk"

    titles = [f.title for f in AndroidAnalyzer().analyze(ctx)]
    assert any("High-risk permissions" in t for t in titles)
    assert any("SMS" in t for t in titles)
    assert any("Dynamic code loading" in t for t in titles)
    assert any("lock the device" in t for t in titles)


def test_android_family_classification(tmp_path):
    apk = _build_apk(tmp_path / "bank.apk")
    ctx = AnalysisContext(info=fileinfo.inspect(apk), content=apk.read_bytes())
    titles = [f.title for f in AndroidAnalyzer().analyze(ctx)]
    assert any("Likely family" in t for t in titles)


def test_standalone_dex_detection(tmp_path):
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"Ljava/lang/Runtime;->exec abortBroadcast")
    info = fileinfo.inspect(dex)
    assert info.file_type == "dex"
    ctx = AnalysisContext(info=info, content=dex.read_bytes())
    titles = [f.title for f in AndroidAnalyzer().analyze(ctx)]
    assert any("shell commands" in t for t in titles)


def test_apk_packer_payload_and_iocs(tmp_path):
    apk = tmp_path / "p.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    "android.permission.SEND_SMS".encode("utf-16-le"))
        zf.writestr("classes.dex",
                    b"dex\n035\x00 sendTextMessage MediaProjection "
                    b"http://evil-apk-c2.com/cfg\x00")
        zf.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF")
        zf.writestr("assets/payload.dex", b"dex\n035\x00")
    ctx = AnalysisContext(info=fileinfo.inspect(apk), content=apk.read_bytes())
    fnds = list(AndroidAnalyzer().analyze(ctx))
    titles = [f.title for f in fnds]
    assert any("packer/protector: Qihoo 360 Jiagu" in t for t in titles)
    assert any("Embedded secondary payload" in t for t in titles)
    assert any("Screen capture" in t for t in titles)
    iocs = [i for f in fnds for i in f.data.get("urls", [])]
    assert "http://evil-apk-c2.com/cfg" in iocs
