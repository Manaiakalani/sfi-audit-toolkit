"""Smoke tests for the FastMCP server surface (tools, resources, dispatch)."""
from __future__ import annotations

import asyncio

import sfi_audit.server as server

EXPECTED_TOOLS = {
    "server_info",
    "list_pillars",
    "get_pillar",
    "get_principles",
    "get_zero_trust_mapping",
    "get_nist_mapping",
    "list_patterns",
    "get_checklist",
    "get_sources",
    "audit_repo",
    "audit_summary",
    "generate_scorecard",
}
EXPECTED_RESOURCES = {
    "sfi://skill",
    "sfi://knowledge/pillars",
    "sfi://knowledge/checklist",
}


def test_all_tools_registered():
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS.issubset(names)


def test_resources_registered():
    resources = asyncio.run(server.mcp.list_resources())
    uris = {str(r.uri) for r in resources}
    assert EXPECTED_RESOURCES.issubset(uris)


def test_server_info_counts():
    info = server.server_info()
    assert info["pillars"] == 6
    assert info["audit_criteria"] >= 40
    assert info["server_version"]


def test_reference_tools_dispatch():
    assert len(server.list_pillars()) == 6
    pillar = server.get_pillar("protect-identities-and-secrets")
    assert pillar["id"] == 1 and pillar["objectives"]
    assert server.get_pillar("nope").get("error")
    assert len(server.get_checklist()) >= 40
    assert server.get_checklist("protect-networks")


def test_audit_tools_dispatch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.yml").write_text(
        "AZURE_CLIENT_SECRET=abcd1234supersecretvalue\n", encoding="utf-8"
    )
    result = server.audit_repo(str(repo))
    assert "results" in result and result["scanned"]["files"] >= 1

    summary = server.audit_summary(str(repo))
    assert "overall" in summary and "pillars" in summary

    # out_dir is a sibling of the audited repo (never written inside the scanned tree)
    card = server.generate_scorecard(str(repo), out_dir=str(tmp_path / "out"))
    assert card["scorecard"]["overall"]["total"] > 0
    assert card["json_path"].endswith(".json")


def test_generate_scorecard_refuses_in_tree_write(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    # out_dir inside the audited tree -> guarded ValueError surfaced as an error dict
    res = server.generate_scorecard(str(tmp_path), out_dir=str(tmp_path / "reports"))
    assert res.get("error")


def test_audit_repo_bad_path_returns_error():
    assert server.audit_repo("Z:/definitely/not/here").get("error")


def test_exclude_reduces_scanned_files(tmp_path):
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    external = tmp_path / "external"          # not a default-ignored dir name
    external.mkdir()
    (external / "lib.py").write_text("y = 2\n", encoding="utf-8")
    full = server.audit_repo(str(tmp_path))
    limited = server.audit_repo(str(tmp_path), exclude="external")
    assert limited["scanned"]["files"] < full["scanned"]["files"]
