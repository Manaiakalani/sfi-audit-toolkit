# SFI Audit Toolkit

**Audit any repository against Microsoft's Secure Future Initiative (SFI) security
pillars.** A versioned, fully-sourced knowledge base of the six SFI engineering
pillars combined with a **read-only** repository/config scanner — delivered as an
**MCP server**, a **GitHub Copilot skill**, and a standalone **CLI harness**. Every
control maps to **Zero Trust** and the **NIST Cybersecurity Framework (CSF 2.0)**,
so you can run repeatable security, compliance, and DevSecOps reviews from the
command line or directly inside an AI agent.

> ⚠️ **Personal project — not affiliated with, authorized by, or endorsed by
> Microsoft.** "Secure Future Initiative" and "SFI" refer to Microsoft's public
> security program; this is an independent, best-effort side project by
> [@Manaiakalani](https://github.com/Manaiakalani), built entirely from Microsoft's
> publicly available documentation (see [`docs/PROVENANCE.md`](./docs/PROVENANCE.md)).
> It is provided "as is" without warranty and is a heuristic aid, **not** a
> compliance certification.

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

## What it audits — the six SFI pillars

The knowledge base covers all six Microsoft SFI engineering pillars, each with
auditable criteria, Zero Trust mapping, and NIST CSF 2.0 functions:

1. **Protect identities and secrets** — phishing-resistant MFA, managed and
   short-lived workload identities, hardened secret vaults, least-privilege
   just-in-time access.
2. **Protect tenants and isolate systems** — tenant inventory and ownership,
   cross-tenant deny-by-default, production/non-production isolation, Microsoft
   Entra application governance.
3. **Protect networks** — deny-by-default segmentation, private management and
   PaaS access, strict egress control, identity-aware encrypted connectivity.
4. **Protect engineering systems** — pinned dependencies and CI/CD actions,
   pipeline least privilege, secret scanning, code-owner review, supply-chain
   integrity.
5. **Monitor and detect threats** — centralized security logging, standardized
   audit telemetry, threat detection coverage.
6. **Accelerate response and remediation** — incident response readiness, a
   published security policy, automated containment and remediation.

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

Released under the [MIT License](./LICENSE) — © 2026 Maximilian Stein. A personal
project, maintained on a best-effort basis.
