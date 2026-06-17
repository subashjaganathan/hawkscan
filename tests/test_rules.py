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
