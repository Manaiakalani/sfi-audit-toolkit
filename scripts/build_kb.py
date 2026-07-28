#!/usr/bin/env python3
"""Build the canonical SFI knowledge base (``data/*.json``) from staging extracts.

This is the reproducible *synthesis* step of the SFI knowledge-base refresh
process:

    staging/*.json   (per-model research extracts)
        -> data/*.json   (canonical, deduplicated knowledge base)

Run it whenever the ``staging`` extracts are refreshed (see
``docs/PROVENANCE.md`` for the full refresh runbook)::

    python scripts/build_kb.py

The script is intentionally dependency-free (standard library only) so it can
run in any environment that has Python 3.9+.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

KB_VERSION = "1.0.0"

# Committed default so an ad-hoc local build is byte-for-byte reproducible.
# Override for a dated rebuild by exporting SOURCE_DATE_EPOCH (reproducible-builds
# convention); see docs/PROVENANCE.md.
DEFAULT_GENERATED_AT = "2026-07-24"


def _generated_at() -> str:
    """Reproducible: honor ``SOURCE_DATE_EPOCH`` when set, otherwise use the
    committed ``DEFAULT_GENERATED_AT`` so builds are deterministic across runs
    and machines (never the wall-clock date)."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).date().isoformat()
    return DEFAULT_GENERATED_AT


GENERATED_AT = _generated_at()

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "staging"
DATA = ROOT / "data"

VALID_SLUGS = [
    "protect-identities-and-secrets",
    "protect-tenants-and-isolate-systems",
    "protect-networks",
    "protect-engineering-systems",
    "monitor-and-detect-threats",
    "accelerate-response-and-remediation",
]
VALID_SEVERITIES = ["critical", "high", "medium", "low"]
VALID_NIST = ["GV", "ID", "PR", "DE", "RS", "RC"]

warnings: list[str] = []


def warn(msg: str) -> None:
    warnings.append(msg)


def load(name: str) -> dict:
    path = STAGING / name
    if not path.exists():
        raise SystemExit(f"ERROR: missing staging file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise SystemExit(f"ERROR: {name} is not valid JSON: {exc}")


def dump(name: str, obj: dict) -> None:
    # write_bytes with an explicit "\n" keeps the KB byte-identical across OSes
    # (text mode would translate "\n" to CRLF on Windows, breaking determinism).
    payload = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    (DATA / name).write_bytes(payload.encode("utf-8"))


def build_pillars() -> dict:
    pillars = load("pillars_1_3.json")["pillars"] + load("pillars_4_6.json")["pillars"]
    pillars = sorted(pillars, key=lambda p: p["id"])

    seen_ids: set[int] = set()
    seen_crit: set[str] = set()
    for p in pillars:
        if p["id"] in seen_ids:
            warn(f"duplicate pillar id: {p['id']}")
        seen_ids.add(p["id"])
        if p.get("slug") not in VALID_SLUGS:
            warn(f"pillar {p['id']} has unexpected slug: {p.get('slug')}")
        for fn in p.get("nist_csf_functions", []):
            if fn not in VALID_NIST:
                warn(f"pillar {p['id']} has unknown NIST function: {fn}")
        for c in p.get("audit_criteria", []):
            key = f"{p['slug']}/{c.get('id')}"
            if key in seen_crit:
                warn(f"duplicate audit criterion id: {key}")
            seen_crit.add(key)
            if c.get("severity") not in VALID_SEVERITIES:
                warn(f"criterion {key} has invalid severity: {c.get('severity')}")

    if {p["id"] for p in pillars} != set(range(1, 7)):
        warn(f"expected pillar ids 1-6, got {sorted(p['id'] for p in pillars)}")

    return {"version": KB_VERSION, "generated_at": GENERATED_AT, "pillars": pillars}


def build_checklists(pillars: list[dict]) -> dict:
    checklist = []
    for p in pillars:
        for c in p.get("audit_criteria", []):
            checklist.append(
                {
                    "id": f"{p['slug']}/{c['id']}",
                    "pillar_id": p["id"],
                    "pillar_slug": p["slug"],
                    "requirement": c.get("requirement", ""),
                    "severity": c.get("severity", "medium"),
                    "how_to_verify": c.get("how_to_verify", ""),
                    "signals": c.get("signals", []),
                    "anti_signals": c.get("anti_signals", []),
                    "source_url": c.get("source_url", ""),
                }
            )
    return {"version": KB_VERSION, "generated_at": GENERATED_AT, "checklist": checklist}


def map_source_type(entry: dict) -> str:
    url = (entry.get("url") or "").lower()
    raw = (entry.get("type") or "").lower()
    if "/security/blog/" in url:
        return "blog"
    if raw == "pdf-report":
        return "progress_report"
    if "nist.gov" in url:
        return "framework"
    if "learn.microsoft.com" in url or raw == "learn":
        return "documentation"
    if raw == "trust-center":
        return "documentation"
    return "other"


def build_sources() -> dict:
    raw = load("sources_raw.json")["sources"]
    sources = []
    for e in sorted(raw, key=lambda entry: entry.get("url", "")):
        sources.append(
            {
                "url": e.get("url", ""),
                "title": e.get("title", ""),
                "type": map_source_type(e),
                "source_type_raw": e.get("type"),
                "retrieved_at": e.get("retrieved_at", GENERATED_AT),
                "readable": e.get("readable", True),
                "used_for": e.get("used_for", ""),
                "report_version": e.get("report_version"),
            }
        )
    return {"version": KB_VERSION, "generated_at": GENERATED_AT, "sources": sources}


def build_principles() -> dict:
    obj = load("principles.json")
    obj.setdefault("version", KB_VERSION)
    obj.setdefault("generated_at", GENERATED_AT)
    return obj


def build_patterns() -> dict:
    patterns = load("patterns.json")
    patterns["patterns"] = sorted(
        patterns.get("patterns", []),
        key=lambda x: (x.get("pillar_id", 99), x.get("title", "")),
    )
    patterns.setdefault("version", KB_VERSION)
    patterns.setdefault("generated_at", GENERATED_AT)
    return patterns


def main() -> int:
    DATA.mkdir(exist_ok=True)

    pillars = build_pillars()
    dump("sfi_pillars.json", pillars)
    dump("sfi_checklists.json", build_checklists(pillars["pillars"]))
    dump("sfi_principles.json", build_principles())
    dump("sfi_patterns.json", build_patterns())
    dump("sources.json", build_sources())

    n_pillars = len(pillars["pillars"])
    n_criteria = sum(len(p.get("audit_criteria", [])) for p in pillars["pillars"])
    n_objectives = sum(len(p.get("objectives", [])) for p in pillars["pillars"])
    n_best = sum(len(p.get("best_practices", [])) for p in pillars["pillars"])

    print(f"SFI knowledge base built (version {KB_VERSION}, {GENERATED_AT}) -> {DATA}")
    print(
        f"  pillars={n_pillars} objectives={n_objectives} "
        f"best_practices={n_best} audit_criteria={n_criteria}"
    )
    for name in (
        "sfi_pillars.json",
        "sfi_checklists.json",
        "sfi_principles.json",
        "sfi_patterns.json",
        "sources.json",
    ):
        print(f"  wrote {name}")

    if warnings:
        print(f"\n{len(warnings)} warning(s):", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
