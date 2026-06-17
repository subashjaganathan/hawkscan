"""Tests for Android APK / DEX analysis."""

from __future__ import annotations

import zipfile

from hawkscan.core import fileinfo
from hawkscan.analyzers.base import AnalysisContext
from hawkscan.analyzers.android_analyzer import AndroidAnalyzer


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


def test_standalone_dex_detection(tmp_path):
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"Ljava/lang/Runtime;->exec abortBroadcast")
    info = fileinfo.inspect(dex)
    assert info.file_type == "dex"
    ctx = AnalysisContext(info=info, content=dex.read_bytes())
    titles = [f.title for f in AndroidAnalyzer().analyze(ctx)]
    assert any("shell commands" in t for t in titles)
