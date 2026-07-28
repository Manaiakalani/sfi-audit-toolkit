"""FastMCP server exposing the SFI knowledge base and repository auditor.

Run it over stdio (the default MCP transport)::

    python -m sfi_audit.server
    # or, once installed:  sfi-audit-mcp

Reference tools expose the six SFI pillars, their objectives, Zero Trust and
NIST CSF mappings, best-practice patterns, auditable checklist, and source
provenance. Scanner tools audit a target repository read-only and produce a
per-pillar scorecard.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from . import __version__, knowledge
from .report import build_scorecard, generate_scorecard as _generate_scorecard
from .scanner import audit_repository

mcp = FastMCP("sfi-audit")


def _parse_pillars(arg: str) -> Optional[List[str]]:
    if not arg:
        return None
    parts = [p.strip() for p in arg.replace(";", ",").split(",") if p.strip()]
    return parts or None


# --------------------------------------------------------------------------- #
# Reference tools (knowledge base)
# --------------------------------------------------------------------------- #
@mcp.tool()
def server_info() -> Dict[str, Any]:
    """Return server version, knowledge-base version, and content counts."""
    pillars = knowledge.get_pillars()
    return {
        "server_version": __version__,
        "kb_version": knowledge.kb_version(),
        "pillars": len(pillars),
        "objectives": sum(len(p.get("objectives", [])) for p in pillars),
        "best_practices": sum(len(p.get("best_practices", [])) for p in pillars),
        "audit_criteria": len(knowledge.get_checklist()),
        "patterns": len(knowledge.get_patterns().get("patterns", [])),
    }


@mcp.tool()
def list_pillars() -> List[Dict[str, Any]]:
    """List the six SFI engineering pillars (id, slug, name, statement, NIST)."""
    return knowledge.pillar_summaries()


@mcp.tool()
def get_pillar(pillar: str) -> Dict[str, Any]:
    """Get a full SFI pillar by id (1-6), slug, or name.

    Includes objectives, Zero Trust mapping, NIST CSF functions, best
    practices, and audit criteria.
    """
    result = knowledge.get_pillar(pillar)
    if result is None:
        return {"error": f"Unknown pillar: {pillar!r}", "valid": knowledge.PILLAR_SLUGS}
    return result


@mcp.tool()
def get_principles() -> Dict[str, Any]:
    """Get SFI security principles, Zero Trust principles, and NIST CSF functions."""
    return knowledge.get_principles()


@mcp.tool()
def get_zero_trust_mapping() -> Dict[str, Any]:
    """Get Zero Trust principle definitions and how each pillar applies them."""
    return knowledge.get_zero_trust_mapping()


@mcp.tool()
def get_nist_mapping() -> Dict[str, Any]:
    """Get the NIST CSF 2.0 function glossary and each pillar's mapped functions."""
    return knowledge.get_nist_mapping()


@mcp.tool()
def list_patterns(pillar: str = "") -> Dict[str, Any]:
    """List SFI patterns & practices, optionally filtered by pillar, plus the report timeline."""
    return knowledge.get_patterns(pillar or None)


@mcp.tool()
def get_checklist(pillar: str = "") -> List[Dict[str, Any]]:
    """Get the flat, scanner-ready SFI audit checklist, optionally filtered by pillar."""
    return knowledge.get_checklist(pillar or None)


@mcp.tool()
def get_sources() -> Dict[str, Any]:
    """Get the provenance ledger of every source used to build the knowledge base."""
    return knowledge.get_sources()


# --------------------------------------------------------------------------- #
# Scanner tools
# --------------------------------------------------------------------------- #
@mcp.tool()
def audit_repo(path: str, pillars: str = "", exclude: str = "") -> Dict[str, Any]:
    """Audit a local repository against the SFI checklist (read-only).

    ``path``: filesystem path to the repository to scan (absolute, or relative to
    the server's working directory — it is expanded and resolved).
    ``pillars``: optional pillar ids/slugs to limit the scan, separated by commas
    or semicolons.
    ``exclude``: optional path prefixes to skip (e.g. ``data,staging``), separated
    by commas or semicolons.
    Returns per-criterion results with redacted evidence.
    """
    try:
        return audit_repository(
            path, pillars=_parse_pillars(pillars), exclude=_parse_pillars(exclude)
        )
    except (NotADirectoryError, FileNotFoundError, ValueError, knowledge.KnowledgeBaseError) as exc:
        return {"error": str(exc)}


@mcp.tool()
def audit_summary(path: str, pillars: str = "", exclude: str = "") -> Dict[str, Any]:
    """Audit a repository and return only the scorecard summary (no evidence detail)."""
    try:
        audit = audit_repository(
            path, pillars=_parse_pillars(pillars), exclude=_parse_pillars(exclude)
        )
    except (NotADirectoryError, FileNotFoundError, ValueError, knowledge.KnowledgeBaseError) as exc:
        return {"error": str(exc)}
    scorecard = build_scorecard(audit)
    return {
        "repository": scorecard["repository"],
        "generated_at": scorecard["generated_at"],
        "kb_version": scorecard["kb_version"],
        "scanned": scorecard.get("scanned", {}),
        "overall": scorecard["overall"],
        "pillars": [
            {k: p[k] for k in ("id", "name", "score", "grade", "passed", "failed", "manual")}
            for p in scorecard["pillars"]
        ],
    }


@mcp.tool()
def generate_scorecard(
    path: str, pillars: str = "", out_dir: str = "", exclude: str = ""
) -> Dict[str, Any]:
    """Audit a repository and produce a per-pillar scorecard (JSON + Markdown).

    If ``out_dir`` is provided, the scorecard is also written there and the file
    paths are returned. ``exclude`` is an optional comma-separated list of path
    prefixes to skip.
    """
    try:
        return _generate_scorecard(
            path,
            pillars=_parse_pillars(pillars),
            out_dir=out_dir or None,
            exclude=_parse_pillars(exclude),
        )
    except (ValueError, OSError, knowledge.KnowledgeBaseError) as exc:
        return {"error": str(exc)}


# --------------------------------------------------------------------------- #
# Resources
# --------------------------------------------------------------------------- #
@mcp.resource("sfi://skill")
def skill_resource() -> str:
    """The unified SFI audit skill document."""
    skill = knowledge.find_data_dir().parent / "skill.md"
    if skill.is_file():
        return skill.read_text(encoding="utf-8")
    return "skill.md is not available in this deployment."


@mcp.resource("sfi://knowledge/pillars")
def pillars_resource() -> str:
    """The raw SFI pillars knowledge base (JSON)."""
    import json

    return json.dumps({"pillars": knowledge.get_pillars()}, indent=2, ensure_ascii=False)


@mcp.resource("sfi://knowledge/checklist")
def checklist_resource() -> str:
    """The flat SFI audit checklist (JSON)."""
    import json

    return json.dumps({"checklist": knowledge.get_checklist()}, indent=2, ensure_ascii=False)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
