#!/usr/bin/env python3
"""SFI audit harness — scan a repository and emit a per-pillar scorecard.

This is a thin, dependency-light CLI around ``sfi_audit.report.generate_scorecard``.
It works whether or not the ``sfi_audit`` package is installed: if it is not on
``sys.path`` it is loaded from the sibling ``mcp_server`` directory.

Examples
--------
Audit a project and print the Markdown scorecard::

    python harness/run_audit.py C:\\path\\to\\repo

Audit and write ``reports/<repo>-sfi-scorecard.{json,md}``::

    python harness/run_audit.py C:\\path\\to\\repo --out reports

Self-audit this repository (excludes the SFI knowledge base so the tool does not
flag its own signal/anti-signal vocabulary)::

    python harness/run_audit.py --self --out reports
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_MCP_PKG = REPO_ROOT / "mcp_server"

# Windows consoles default to cp1252 and choke on the scorecard's box-drawing
# and redaction glyphs; force UTF-8 so piping/printing never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

# Allow running straight from a checkout without installing the package.
if str(_MCP_PKG) not in sys.path:
    sys.path.insert(0, str(_MCP_PKG))

from sfi_audit import report  # noqa: E402

# When self-auditing, skip the SFI tool's own knowledge base, generated
# artifacts, deliberately-insecure test data, and CLI/dev tooling. Those files
# intentionally contain the audit vocabulary (secret regexes, insecure-config
# literals), planted fake credentials, or use console output (print/console.log)
# that is legitimate for command-line tools but not for audited services. The
# meaningful surface that remains is the product code under mcp_server/sfi_audit/
# plus the repository's root configuration files.
SELF_EXCLUDES = [
    "data",
    "staging",
    "reports",
    "docs",
    ".venv",
    "skill.md",
    "scripts",          # build/refresh CLI tooling (uses print() for output)
    "harness",          # test harness runner + fixtures (CLI + planted secrets)
    "mcp_server/tests",
]


def _split(value: str) -> list[str] | None:
    if not value:
        return None
    parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
    return parts or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_audit.py",
        description="Audit a repository against the Microsoft SFI checklist.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to the repository to audit (omit when using --self).",
    )
    parser.add_argument(
        "--self",
        dest="self_audit",
        action="store_true",
        help="Audit this SFI repository itself (dogfood), excluding the knowledge base.",
    )
    parser.add_argument(
        "--pillars",
        default="",
        help="Comma-separated pillar ids/slugs to limit the scan (default: all).",
    )
    parser.add_argument(
        "--exclude",
        default="",
        help="Comma-separated path prefixes to skip (e.g. 'vendor,third_party').",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Directory to write <repo>-sfi-scorecard.{json,md} into.",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json", "both"],
        default="md",
        help="What to print to stdout (default: md).",
    )
    args = parser.parse_args(argv)

    if args.self_audit:
        target = REPO_ROOT
        excludes = list(SELF_EXCLUDES)
        extra = _split(args.exclude)
        if extra:
            excludes.extend(extra)
    else:
        if not args.path:
            parser.error("a repository path is required (or pass --self)")
        target = Path(args.path).expanduser()
        excludes = _split(args.exclude)

    if not Path(target).is_dir():
        parser.error(f"not a directory: {target}")

    try:
        result = report.generate_scorecard(
            target,
            pillars=_split(args.pillars),
            out_dir=args.out or None,
            exclude=excludes,
            allow_in_tree=bool(args.self_audit),
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format in ("json", "both"):
        print(json.dumps(result["scorecard"], indent=2, ensure_ascii=False))
    if args.format in ("md", "both"):
        print(result["markdown"])

    if result.get("json_path"):
        print(f"[written] {result['json_path']}", file=sys.stderr)
        print(f"[written] {result['markdown_path']}", file=sys.stderr)

    # Non-zero exit if any hard finding exists, so CI can gate on it.
    return 1 if result["scorecard"]["overall"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
