"""Tests for API capability categorization and MITRE ATT&CK mapping."""

from __future__ import annotations

from hawkscan.intel import capabilities as cap


def test_categorize_maps_apis_to_categories_and_techniques():
    caps, techs = cap.categorize(
        ["VirtualAllocEx", "WriteProcessMemory", "InternetOpenA", "GetAsyncKeyState"]
    )
    assert "Process Injection" in caps
    assert "Networking" in caps
    assert "Keylogging / Input Capture" in caps
    assert "T1055" in techs            # process injection
    assert "T1056.001" in techs        # keylogging


def test_suffix_folding_resolves_variants():
    # RegSetValueExW should fold to the RegSetValueExA entry's behaviour.
    caps, _ = cap.categorize(["RegSetValueExW"])
    assert "Persistence" in caps


def test_scan_text_finds_api_tokens():
    blob = "junk\nWriteProcessMemory\nmore junk CreateRemoteThread end"
    found = cap.scan_text(blob)
    assert "WriteProcessMemory" in found
    assert "CreateRemoteThread" in found


def test_injection_combo_requires_multiple_apis():
    # Two injection primitives -> classic injection combo fires.
    hits = cap.detect_combinations(
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    )
    names = {h["name"] for h in hits}
    assert "Classic process injection" in names
    assert any(h["severity"] == "high" for h in hits)


def test_single_common_api_does_not_trigger_injection_combo():
    # MapViewOfFile alone (common in benign software) must NOT flag injection.
    hits = cap.detect_combinations({"MapViewOfFile"})
    names = {h["name"] for h in hits}
    assert "Classic process injection" not in names


def test_keylogging_combo_single_api():
    hits = cap.detect_combinations({"GetAsyncKeyState"})
    assert any(h["name"] == "Keylogging" for h in hits)


def test_new_categories_present():
    caps, _ = cap.categorize(["GetClipboardData", "DeleteFileW", "Sleep"])
    assert "Collection" in caps
    assert "Defense Evasion" in caps


def test_capability_output_includes_addresses_key(tmp_path):
    from hawkscan.core.engine import Engine
    f = tmp_path / "inj.exe"
    f.write_bytes(b"MZ" + b"WriteProcessMemory CreateRemoteThread VirtualAllocEx")
    res = Engine().scan(f)
    # Each capability entry exposes an 'addresses' map (empty without pefile).
    for cat, entry in res.capabilities.items():
        assert "apis" in entry and "addresses" in entry


def test_expanded_api_coverage():
    # Spot-check APIs added in the coverage expansion.
    caps, techs = cap.categorize(
        ["NtWriteVirtualMemory", "DnsQuery_A", "CredReadA", "GetAdaptersInfo"])
    assert "Process Injection" in caps
    assert "Networking" in caps
    assert "Credential Access" in caps
    assert "System Discovery" in caps
    assert len(cap.API_DB) >= 130
