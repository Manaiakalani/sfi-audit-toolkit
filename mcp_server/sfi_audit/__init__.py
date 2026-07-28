"""SFI audit — Microsoft Secure Future Initiative knowledge base and scanner.

This package provides:

* :mod:`sfi_audit.knowledge` — loads the canonical SFI knowledge base
  (``data/*.json``) and exposes typed query helpers.
* :mod:`sfi_audit.scanner` — a read-only heuristic scanner that audits a
  target repository against the SFI checklist.
* :mod:`sfi_audit.report` — turns scan results into a per-pillar scorecard
  (JSON + Markdown).
* :mod:`sfi_audit.server` — a FastMCP server exposing the knowledge base and
  scanner as MCP tools and resources.

The scanner is strictly read-only: it reads files from the target path, never
writes to it, and never transmits repository contents anywhere.
"""

__version__ = "1.0.0"
