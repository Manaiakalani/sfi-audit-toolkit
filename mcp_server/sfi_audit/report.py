"""Turn scanner results into a per-pillar SFI scorecard (JSON + Markdown)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from . import knowledge
from .scanner import SEVERITY_WEIGHT, audit_repository

_GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _grade(score: Optional[int]) -> str:
    if score is None:
        return "N/A"
    for threshold, letter in _GRADES:
        if score >= threshold:
            return letter
    return "F"


def _score(results: List[Dict[str, Any]]) -> Optional[int]:
    earned = possible = 0
    for r in results:
        weight = SEVERITY_WEIGHT.get(r.get("severity", "medium"), 2)
        status = r.get("status")
        if status == "pass":
            earned += weight
            possible += weight
        elif status == "fail":
            possible += weight
    if not possible:
        return None
    score = round(100 * earned / possible)
    # Never let rounding report a misleading extreme: stay below 100 while any
    # weight is unearned, and above 0 while any weight is earned, so a lone
    # failure can never display as a perfect 100 (nor a lone pass as 0).
    if score >= 100 and earned < possible:
        return 99
    if score <= 0 and earned > 0:
        return 1
    return score


def _finding(r: Dict[str, Any], pillar_name: str) -> Dict[str, Any]:
    return {
        "id": r["id"],
        "pillar_id": r["pillar_id"],
        "pillar_slug": r["pillar_slug"],
        "pillar_name": pillar_name,
        "severity": r.get("severity", "medium"),
        "requirement": r["requirement"],
        "how_to_verify": r.get("how_to_verify", ""),
        "source_url": r.get("source_url", ""),
        "note": r.get("note", ""),
        "evidence": r.get("anti_signal_hits", [])[:8],
    }


def build_scorecard(audit: Dict[str, Any]) -> Dict[str, Any]:
    names = {p["id"]: p["name"] for p in knowledge.pillar_summaries()}
    results = audit["results"]

    pillars = []
    all_findings: List[Dict[str, Any]] = []
    all_manual: List[Dict[str, Any]] = []
    tot_pass = tot_fail = tot_manual = 0

    for pid in range(1, 7):
        pres = [r for r in results if r["pillar_id"] == pid]
        if not pres:
            continue
        passed = sum(1 for r in pres if r["status"] == "pass")
        failed = sum(1 for r in pres if r["status"] == "fail")
        manual = sum(1 for r in pres if r["status"] == "manual")
        tot_pass += passed
        tot_fail += failed
        tot_manual += manual
        score = _score(pres)
        findings = [_finding(r, names.get(pid, "")) for r in pres if r["status"] == "fail"]
        all_findings.extend(findings)
        all_manual.extend(
            {
                "id": r["id"],
                "pillar_id": pid,
                "pillar_name": names.get(pid, ""),
                "requirement": r["requirement"],
                "how_to_verify": r.get("how_to_verify", ""),
            }
            for r in pres
            if r["status"] == "manual"
        )
        pillars.append(
            {
                "id": pid,
                "slug": pres[0]["pillar_slug"],
                "name": names.get(pid, ""),
                "score": score,
                "grade": _grade(score),
                "passed": passed,
                "failed": failed,
                "manual": manual,
                "total": len(pres),
                "findings": findings,
            }
        )

    all_findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["pillar_id"]))
    overall_score = _score(results)
    scanned = audit.get("scanned", {})

    return {
        "repository": audit["repository"],
        "generated_at": audit.get("generated_at", datetime.now(timezone.utc).isoformat()),
        "kb_version": audit.get("kb_version", "unknown"),
        "scanned": scanned,
        "overall": {
            "score": overall_score,
            "grade": _grade(overall_score),
            "incomplete": bool(scanned.get("truncated")),
            "passed": tot_pass,
            "failed": tot_fail,
            "manual": tot_manual,
            "total": tot_pass + tot_fail + tot_manual,
        },
        "pillars": pillars,
        "findings": all_findings,
        "manual_review": all_manual,
    }


def _bar(score: Optional[int]) -> str:
    if score is None:
        return "—"
    filled = round(score / 10)
    return "█" * filled + "░" * (10 - filled)


def render_markdown(scorecard: Dict[str, Any]) -> str:
    o = scorecard["overall"]
    lines: List[str] = []
    lines.append("# SFI Audit Scorecard")
    lines.append("")
    lines.append(f"- **Repository:** `{scorecard['repository']}`")
    lines.append(f"- **Generated:** {scorecard['generated_at']}")
    lines.append(f"- **Knowledge base:** SFI KB v{scorecard['kb_version']}")
    score_txt = "N/A" if o["score"] is None else f"{o['score']}/100"
    lines.append(f"- **Overall:** **{score_txt} ({o['grade']})** {_bar(o['score'])}")
    lines.append(
        f"- **Automated checks:** {o['passed']} pass · {o['failed']} fail · "
        f"{o['manual']} need manual review ({o['total']} total)"
    )
    lines.append("")
    lines.append(
        "> `pass` = automated evidence the control is present · `fail` = a likely "
        "violation was matched · `manual` = no automated signal, verify by hand. "
        "This scorecard is a heuristic aid, not a compliance certification."
    )
    lines.append("")

    if scorecard.get("scanned", {}).get("truncated"):
        lines.append(
            "> ⚠️ **Incomplete scan:** the repository exceeded the scanner's file/size "
            "limits, so some files were not read. Absence-based `pass` results (e.g. "
            "\"no committed .env\") and the score above may be incomplete — re-run on a "
            "smaller subtree or add `exclude`s to verify."
        )
        lines.append("")

    lines.append("## Pillars")
    lines.append("")
    lines.append("| # | Pillar | Score | Pass | Fail | Manual |")
    lines.append("| - | ------ | ----- | ---- | ---- | ------ |")
    for p in scorecard["pillars"]:
        s = "N/A" if p["score"] is None else f"{p['score']} ({p['grade']})"
        lines.append(
            f"| {p['id']} | {p['name']} | {s} | {p['passed']} | {p['failed']} | {p['manual']} |"
        )
    lines.append("")

    findings = scorecard["findings"]
    lines.append(f"## Findings ({len(findings)})")
    lines.append("")
    if not findings:
        lines.append("No automated violations detected. ✅")
    else:
        for f in findings:
            lines.append(f"### [{f['severity'].upper()}] {f['requirement']}")
            lines.append("")
            lines.append(f"- **Pillar {f['pillar_id']}:** {f['pillar_name']}")
            lines.append(f"- **Check:** `{f['id']}`")
            if f["how_to_verify"]:
                lines.append(f"- **How to verify / fix:** {f['how_to_verify']}")
            for ev in f["evidence"][:3]:
                loc = ev.get("file", "")
                if ev.get("line"):
                    loc += f":{ev['line']}"
                detail = f" — `{ev['snippet']}`" if ev.get("snippet") else ""
                pat = ev.get("pattern", "")
                lines.append(f"  - `{loc}` matched *{pat}*{detail}")
            if f["note"]:
                lines.append(f"- _{f['note']}_")
            if f["source_url"]:
                lines.append(f"- Reference: {f['source_url']}")
            lines.append("")

    manual = scorecard["manual_review"]
    if manual:
        lines.append(f"## Manual review needed ({len(manual)})")
        lines.append("")
        lines.append(
            "These SFI controls could not be verified from source and require manual review "
            "(often tenant-, policy-, or platform-level configuration):"
        )
        lines.append("")
        for m in manual:
            lines.append(f"- **P{m['pillar_id']}** `{m['id']}` — {m['requirement']}")
        lines.append("")

    lines.append("---")
    lines.append(
        "_Generated by the SFI audit MCP server. Pillars, criteria, and provenance are "
        "defined in the repository's `data/` knowledge base; see `docs/PROVENANCE.md`._"
    )
    return "\n".join(lines) + "\n"


def generate_scorecard(
    path: Union[str, Path],
    pillars: Optional[Sequence[Union[int, str]]] = None,
    out_dir: Optional[Union[str, Path]] = None,
    exclude: Optional[Sequence[str]] = None,
    allow_in_tree: bool = False,
) -> Dict[str, Any]:
    """Audit ``path`` and build a scorecard; optionally write JSON + Markdown.

    Writing is refused when ``out_dir`` resolves to the audited repository or a
    descendant of it (which would mutate the scanned tree and violate the
    read-only guarantee), unless ``allow_in_tree`` is explicitly set for a
    deliberate in-repo artifact (e.g. the project's own ``reports/`` dogfood).
    """
    import json

    audit = audit_repository(path, pillars=pillars, exclude=exclude)
    scorecard = build_scorecard(audit)
    markdown = render_markdown(scorecard)
    result: Dict[str, Any] = {"scorecard": scorecard, "markdown": markdown}

    if out_dir is not None:
        out = Path(out_dir).expanduser().resolve()
        root = Path(scorecard["repository"]).resolve()
        if not allow_in_tree and (out == root or root in out.parents):
            raise ValueError(
                f"Refusing to write the scorecard inside the audited repository "
                f"({out}). Choose an out_dir outside {root}, or set "
                f"allow_in_tree=True for a deliberate in-repo artifact."
            )
        out.mkdir(parents=True, exist_ok=True)
        stem = Path(scorecard["repository"]).name or "repo"
        json_path = out / f"{stem}-sfi-scorecard.json"
        md_path = out / f"{stem}-sfi-scorecard.md"
        json_path.write_text(json.dumps(scorecard, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        md_path.write_text(markdown, encoding="utf-8")
        result["json_path"] = str(json_path)
        result["markdown_path"] = str(md_path)
    return result
