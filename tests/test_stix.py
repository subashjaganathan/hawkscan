"""Tests for STIX 2.1 IOC export."""

from __future__ import annotations

from hawk_malware_scan.core.engine import Engine
from hawk_malware_scan import stix


def test_stix_bundle_has_file_and_indicators(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"beacon to http://c2.evil.example/gate and 45.77.88.99")
    res = Engine().scan(f)
    bundle = stix.build_bundle([res])

    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert "file" in types
    assert "indicator" in types
    # The file-hash indicator pattern is present.
    assert any("file:hashes" in o.get("pattern", "")
               for o in bundle["objects"] if o["type"] == "indicator")
    # The C2 URL became a URL indicator.
    assert any("url:value" in o.get("pattern", "")
               for o in bundle["objects"] if o["type"] == "indicator")
