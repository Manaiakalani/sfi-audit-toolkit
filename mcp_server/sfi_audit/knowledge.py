"""Load and query the canonical SFI knowledge base (``data/*.json``).

The knowledge base lives outside this package (at the repository's ``data/``
directory) so that it is a single source of truth shared by the ``skill.md``
guidance, the ``scripts/build_kb.py`` build step, and this MCP server.

Location resolution order:

1. ``$SFI_DATA_DIR`` environment variable (must contain ``sfi_pillars.json``).
2. The first ancestor directory of this file that contains
   ``data/sfi_pillars.json``.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

PILLAR_SLUGS = [
    "protect-identities-and-secrets",
    "protect-tenants-and-isolate-systems",
    "protect-networks",
    "protect-engineering-systems",
    "monitor-and-detect-threats",
    "accelerate-response-and-remediation",
]

_DATA_FILES = {
    "pillars": "sfi_pillars.json",
    "principles": "sfi_principles.json",
    "patterns": "sfi_patterns.json",
    "checklists": "sfi_checklists.json",
    "sources": "sources.json",
}


class KnowledgeBaseError(RuntimeError):
    """Raised when the SFI knowledge base cannot be located or parsed."""


def find_data_dir() -> Path:
    """Return the directory containing the SFI knowledge-base JSON files."""
    env = os.environ.get("SFI_DATA_DIR")
    if env:
        candidate = Path(env).expanduser()
        if (candidate / _DATA_FILES["pillars"]).is_file():
            return candidate
        raise KnowledgeBaseError(
            f"SFI_DATA_DIR is set to {candidate!s} but it does not contain "
            f"{_DATA_FILES['pillars']}."
        )

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "data"
        if (candidate / _DATA_FILES["pillars"]).is_file():
            return candidate
    raise KnowledgeBaseError(
        "Could not locate the SFI knowledge base. Set SFI_DATA_DIR to the "
        "directory containing sfi_pillars.json."
    )


@lru_cache(maxsize=None)
def _load(name: str) -> Dict[str, Any]:
    path = find_data_dir() / _DATA_FILES[name]
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise KnowledgeBaseError(f"Missing knowledge-base file: {path}") from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise KnowledgeBaseError(f"Invalid JSON in {path}: {exc}") from exc


def clear_cache() -> None:
    """Clear the in-memory cache (used by tests and after a KB refresh)."""
    _load.cache_clear()


# --------------------------------------------------------------------------- #
# Query helpers
# --------------------------------------------------------------------------- #
def kb_version() -> str:
    return _load("pillars").get("version", "unknown")


def get_pillars() -> List[Dict[str, Any]]:
    return _load("pillars")["pillars"]


def pillar_summaries() -> List[Dict[str, Any]]:
    """Lightweight list of pillars (id, slug, name, statement, NIST functions)."""
    return [
        {
            "id": p["id"],
            "slug": p["slug"],
            "name": p["name"],
            "statement": p.get("statement", ""),
            "nist_csf_functions": p.get("nist_csf_functions", []),
        }
        for p in get_pillars()
    ]


def _match_pillar(p: Dict[str, Any], key: Union[int, str]) -> bool:
    if isinstance(key, bool):  # bool is an int subclass; never a pillar id
        return False
    if isinstance(key, int):
        return p["id"] == key
    k = str(key).strip()
    if k.isascii() and k.isdigit():
        # Bound the length before int() so a pathologically long digit string
        # cannot trip Python's integer-string-conversion limit (pillar ids are 1-6).
        return len(k) <= 3 and p["id"] == int(k)
    key_l = k.lower()
    return p["slug"] == key_l or p["name"].lower() == key_l


def get_pillar(key: Union[int, str]) -> Optional[Dict[str, Any]]:
    """Return a full pillar by id (1-6), slug, or name; ``None`` if unknown."""
    for p in get_pillars():
        if _match_pillar(p, key):
            return p
    return None


def get_principles() -> Dict[str, Any]:
    return _load("principles")


def get_zero_trust_mapping() -> Dict[str, Any]:
    """Zero Trust principle definitions plus how each pillar applies them."""
    return {
        "principles": get_principles().get("zero_trust_principles", []),
        "pillars": [
            {
                "id": p["id"],
                "slug": p["slug"],
                "name": p["name"],
                "zero_trust": p.get("zero_trust", {}),
            }
            for p in get_pillars()
        ],
    }


def get_nist_mapping() -> Dict[str, Any]:
    """NIST CSF 2.0 function glossary plus each pillar's mapped functions."""
    return {
        "functions": get_principles().get("nist_csf_functions", []),
        "pillars": [
            {
                "id": p["id"],
                "slug": p["slug"],
                "name": p["name"],
                "nist_csf_functions": p.get("nist_csf_functions", []),
                "nist_csf_detail": p.get("nist_csf_detail", ""),
            }
            for p in get_pillars()
        ],
    }


def get_patterns(pillar: Optional[Union[int, str]] = None) -> Dict[str, Any]:
    data = _load("patterns")
    if pillar is None:
        return data
    target = get_pillar(pillar)
    slug = target["slug"] if target else str(pillar)
    return {
        "patterns": [p for p in data.get("patterns", []) if p.get("pillar_slug") == slug],
        "reports": data.get("reports", []),
    }


def get_checklist(pillar: Optional[Union[int, str]] = None) -> List[Dict[str, Any]]:
    items = _load("checklists")["checklist"]
    if pillar is None:
        return items
    target = get_pillar(pillar)
    slug = target["slug"] if target else str(pillar)
    return [c for c in items if c.get("pillar_slug") == slug]


def get_sources() -> Dict[str, Any]:
    return _load("sources")
