"""Integrity tests for the SFI knowledge base loaded from data/*.json."""
from __future__ import annotations

from sfi_audit import knowledge

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
NIST_FUNCTIONS = {"GV", "ID", "PR", "DE", "RS", "RC"}
ZT_KEYS = {"verify_explicitly", "use_least_privilege", "assume_breach"}


def test_six_pillars_with_expected_slugs():
    pillars = knowledge.get_pillars()
    assert len(pillars) == 6
    ids = [p["id"] for p in pillars]
    assert ids == [1, 2, 3, 4, 5, 6]
    assert [p["slug"] for p in pillars] == list(knowledge.PILLAR_SLUGS)


def test_pillars_have_required_structure():
    for p in knowledge.get_pillars():
        assert p["name"] and p["statement"]
        assert ZT_KEYS.issubset(p["zero_trust"].keys())
        funcs = set(p["nist_csf_functions"])
        assert funcs and funcs.issubset(NIST_FUNCTIONS)
        assert p["objectives"], f"pillar {p['id']} has no objectives"


def test_get_pillar_by_id_slug_and_name():
    by_id = knowledge.get_pillar("1")
    by_slug = knowledge.get_pillar("protect-identities-and-secrets")
    assert by_id is not None and by_slug is not None
    assert by_id["id"] == by_slug["id"] == 1
    by_name = knowledge.get_pillar(by_id["name"])
    assert by_name is not None and by_name["id"] == 1
    assert knowledge.get_pillar("does-not-exist") is None


def test_checklist_is_well_formed_and_unique():
    checklist = knowledge.get_checklist()
    assert len(checklist) >= 40
    seen = set()
    for c in checklist:
        assert c["id"] not in seen, f"duplicate criterion id {c['id']}"
        seen.add(c["id"])
        assert c["severity"] in VALID_SEVERITIES
        assert c["pillar_slug"] in knowledge.PILLAR_SLUGS
        assert c["requirement"]
        # every criterion must give the scanner something to match on
        assert c.get("signals") or c.get("anti_signals")
        assert c.get("source_url", "").startswith("http")


def test_checklist_filter_by_pillar():
    subset = knowledge.get_checklist("protect-identities-and-secrets")
    assert subset
    assert all(c["pillar_slug"] == "protect-identities-and-secrets" for c in subset)


def test_principles_and_mappings_present():
    principles = knowledge.get_principles()
    assert principles.get("security_principles")
    zt = knowledge.get_zero_trust_mapping()
    zt_keys = {d["key"] for d in zt.get("principles", [])}
    assert ZT_KEYS.issubset(zt_keys)
    nist = knowledge.get_nist_mapping()
    nist_codes = {d["code"] for d in nist.get("functions", [])}
    assert NIST_FUNCTIONS.issubset(nist_codes)


def test_sources_ledger_present():
    sources = knowledge.get_sources()
    items = sources.get("sources", sources) if isinstance(sources, dict) else sources
    assert items, "provenance ledger should not be empty"


def test_every_checklist_source_url_is_in_the_ledger():
    # Provenance invariant (round-11 gemini finding g2): every URL a criterion
    # cites must be traceable in the sources ledger, so the audit's citations are
    # always auditable back to a recorded, dated source.
    sources = knowledge.get_sources()
    items = sources.get("sources", sources) if isinstance(sources, dict) else sources
    ledger = {s["url"].split("#")[0].rstrip("/") for s in items}
    checklist = knowledge.get_checklist()
    cited = {
        (c.get("source_url") or "").split("#")[0].rstrip("/")
        for c in checklist
        if c.get("source_url")
    }
    missing = sorted(cited - ledger)
    assert not missing, f"checklist source_urls absent from ledger: {missing}"


def test_security_principles_are_the_canonical_three():
    # Round-11 gemini finding g1: the KB must name Microsoft's three security
    # principles (secure by design/default/operations); the Innovate/Implement/
    # Guide verbs are preserved separately as the principle *application*.
    principles = knowledge.get_principles()
    names = {p["name"].lower() for p in principles["security_principles"]}
    assert names == {"secure by design", "secure by default", "secure operations"}
    verbs = {p["name"] for p in principles.get("security_principle_application", [])}
    assert verbs == {"Innovate", "Implement", "Guide"}

