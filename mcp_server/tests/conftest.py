"""Shared pytest configuration for the SFI audit test suite.

Ensures the ``sfi_audit`` package is importable even when it has not been
installed (``pip install -e``), by adding the package root to ``sys.path``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _TESTS_DIR.parent          # .../mcp_server
_REPO_ROOT = _PKG_ROOT.parent          # repo root

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

FIXTURES = _REPO_ROOT / "harness" / "fixtures"
REPO_ROOT = _REPO_ROOT
