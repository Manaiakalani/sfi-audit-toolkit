# sfi-audit (MCP server)

Python MCP server for auditing a repository against Microsoft's **Secure Future
Initiative (SFI)**. It serves the SFI knowledge base (six pillars, objectives,
Zero Trust + NIST CSF mappings, patterns, and a 42-criterion checklist) and runs
a **read-only** repo/config scanner that produces a per-pillar scorecard.

This package is one component of the SFI audit repository. See the repository
root [`README.md`](../README.md) and [`skill.md`](../skill.md) for the full
picture, and [`docs/`](../docs) for provenance and architecture.

## Install

```bash
python -m pip install -e .
```

The knowledge base lives outside this package (at the repo's `data/`). The
server locates it via `$SFI_DATA_DIR`, or by searching ancestor directories for
`data/sfi_pillars.json`.

## Run

```bash
python -m sfi_audit.server      # stdio MCP transport
# or, via the installed console script:
sfi-audit-mcp
```

## Tools

Reference: `server_info`, `list_pillars`, `get_pillar`, `get_principles`,
`get_zero_trust_mapping`, `get_nist_mapping`, `list_patterns`, `get_checklist`,
`get_sources`.

Scanner (read-only): `audit_repo`, `audit_summary`, `generate_scorecard`.

Resources: `sfi://skill`, `sfi://knowledge/pillars`, `sfi://knowledge/checklist`.

## Package modules

| Module | Responsibility |
| ------ | -------------- |
| `knowledge.py` | Load & query `data/*.json` (single source of truth) |
| `matching.py` | Classify signal/anti-signal tokens (regex vs literal) + redact secrets |
| `scanner.py` | Read-only repo walk + per-criterion evaluation |
| `checks/structural.py` | 5 deterministic structural checks |
| `report.py` | Build the JSON + Markdown scorecard |
| `server.py` | FastMCP entrypoint (tools + resources) |

## Test

```bash
python -m pytest tests -q
```
