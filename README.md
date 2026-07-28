# SFI Audit — Skill & MCP Server

A single, reusable capability to **audit any project against Microsoft's Secure
Future Initiative (SFI)**. It combines a versioned, fully-sourced knowledge base
of the six SFI engineering pillars with a **read-only** repository/config
scanner, exposed as an MCP server, a Copilot skill, and a standalone harness.

- **Knowledge base** — [`data/*.json`](./data): 6 pillars, 28 objectives, 24
  best practices, **42 audit criteria**, Zero Trust + NIST CSF 2.0 mappings, a
  7-entry patterns catalog, and a 29-source provenance ledger.
- **Skill** — [`skill.md`](./skill.md): teaches an agent how to run an SFI audit.
- **MCP server** — [`mcp_server/`](./mcp_server): 12 tools (reference + scanner)
  and 3 resources over stdio.
- **Harness** — [`harness/`](./harness): CLI runner, scorecard, and golden
  regression fixtures.
- **Docs** — [`docs/`](./docs): sources runbook, provenance/refresh procedure,
  and architecture (incl. the multi-model build record).

## Quickstart

```powershell
# 1. Create an isolated environment and install the server (editable)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e mcp_server

# 2. Audit a project -> writes reports\<repo>-sfi-scorecard.{json,md}
.\.venv\Scripts\python.exe harness\run_audit.py C:\path\to\project --out reports

# 3. Dogfood: audit this repo (excludes the KB + test fixtures)
.\.venv\Scripts\python.exe harness\run_audit.py --self --out reports

# 4. Run the tests
.\.venv\Scripts\python.exe -m pytest mcp_server\tests -q
```

The scanner is **strictly read-only**: it never writes to the target and never
transmits repository contents anywhere. Secret-looking values are redacted out
of all evidence before it is returned.

## Using it as an MCP server

Register the server with an MCP client (e.g. Copilot CLI) so the tools are
available in chat. See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md#deployment)
for the exact `mcp-config.json` entry. Once registered:

- `list_pillars`, `get_pillar`, `get_checklist`, `list_patterns`, … — reference.
- `audit_repo`, `audit_summary`, `generate_scorecard` — active, read-only scan.

## How the audit works

Each of the 42 criteria carries machine-detectable `signals` (evidence a control
is present) and `anti_signals` (likely violations). The scanner walks the repo,
evaluates every criterion, merges five deterministic structural checks (tracked
`.env`, unpinned CI actions, unpinned dependencies, CODEOWNERS, SECURITY.md), and
produces a per-pillar scorecard:

- **fail** (anti-signal matched) · **pass** (signal matched, no anti-signal) ·
  **manual** (no signal — verify by hand).
- Score = `100 × earned / possible` over *determined* criteria; grades A–F.

See [`skill.md`](./skill.md) for the full workflow and scoring model.

## Repository layout

```
data/        Canonical knowledge base (single source of truth)
skill.md     Unified SFI audit skill (YAML frontmatter + guidance)
mcp_server/  FastMCP server: knowledge, scanner, checks, report, tests
harness/     CLI runner + scorecard + golden fixtures
scripts/     build_kb.py — rebuilds data/ from staging/ (refresh step)
staging/     Per-model research fragments (inputs to build_kb.py)
docs/        SOURCES.md, PROVENANCE.md, ARCHITECTURE.md
reports/     Generated scorecards (e.g. this repo's self-audit)
```

## Refreshing the knowledge base

The pillars evolve as Microsoft publishes new SFI guidance and progress reports.
To update what we audit, follow the runbook in
[`docs/PROVENANCE.md`](./docs/PROVENANCE.md): re-extract from the durable Microsoft
Learn pages + latest progress report into `staging/`, run
`python scripts/build_kb.py`, review the diff, bump the KB version, and re-run the
tests. Guidance and the scanner both read `data/`, so they never drift.

## License

MIT.
