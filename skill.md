---
name: sfi-audit
version: 1.0.0
description: >-
  Audit a repository or project against Microsoft's Secure Future Initiative
  (SFI). Provides the six SFI engineering pillars, their objectives, Zero Trust
  and NIST CSF 2.0 mappings, a patterns-and-practices catalog, and a read-only
  repo/config scanner that produces a per-pillar scorecard with severities and
  remediation. Use when asked to review, harden, or "SFI-check" a codebase, or
  to explain what any SFI pillar requires.
license: MIT
keywords:
  - security
  - secure future initiative
  - sfi
  - zero trust
  - nist csf
  - audit
  - supply chain
mcp_server: sfi-audit
data_source: ./data
---

# SFI Audit Skill

This skill audits a project against Microsoft's **Secure Future Initiative
(SFI)** — the six engineering pillars Microsoft uses to make security the top
priority across identity, tenants, networks, engineering systems, monitoring,
and response. It pairs a **versioned knowledge base** (`data/*.json`) with an
**MCP server** (`sfi-audit`) that exposes both reference lookups and an active,
read-only scanner.

Everything the skill asserts comes from the knowledge base, which is built from
official Microsoft sources with full provenance. See
[`docs/PROVENANCE.md`](./docs/PROVENANCE.md) for how the pillars are pulled and
[`docs/SOURCES.md`](./docs/SOURCES.md) for the exact refresh runbook.

## The six SFI pillars

| # | Pillar | Slug | NIST CSF | Focus |
| - | ------ | ---- | -------- | ----- |
| 1 | Protect identities and secrets | `protect-identities-and-secrets` | PR, DE | Phishing-resistant MFA, managed/short-lived workload identities, no hardcoded secrets, vaulted keys, rotation |
| 2 | Protect tenants and isolate systems | `protect-tenants-and-isolate-systems` | ID, PR, DE | Tenant inventory & ownership, app governance, credential isolation across boundaries, remove legacy/unused |
| 3 | Protect networks | `protect-networks` | ID, PR | Network asset inventory, segmentation, private management/PaaS access, default-deny egress, policy-as-code |
| 4 | Protect engineering systems | `protect-engineering-systems` | ID, PR, GV | Pinned CI actions & dependencies, code-owner review, pipeline least privilege, secret scanning |
| 5 | Monitor and detect threats | `monitor-and-detect-threats` | ID, PR, DE, RS | Central logging, telemetry coverage, retention, threat detection & correlation |
| 6 | Accelerate response and remediation | `accelerate-response-and-remediation` | ID, RC, RS, GV | Security policy, coordinated disclosure, response ownership, timely remediation |

**Guiding principles.** SFI is delivered through three security principles —
*secure by design*, *secure by default*, *secure operations* — which Microsoft
applies to *innovate*, *implement*, and *guide* (preserved in the KB as
`security_principle_application`). Every pillar also applies the three **Zero
Trust** principles: *verify explicitly*, *use least privilege*, *assume breach*.

## MCP tool surface (`sfi-audit` server)

### Reference tools (knowledge base)
- `server_info()` — server + KB version and content counts.
- `list_pillars()` — the six pillars (id, slug, name, statement, NIST functions).
- `get_pillar(pillar)` — full pillar by id `1`–`6`, slug, or name (objectives,
  Zero Trust mapping, NIST functions, best practices, audit criteria).
- `get_principles()` — security principles, Zero Trust principles, NIST CSF glossary.
- `get_zero_trust_mapping()` / `get_nist_mapping()` — cross-walks per pillar.
- `list_patterns(pillar?)` — patterns-and-practices catalog + progress-report timeline.
- `get_checklist(pillar?)` — the flat, scanner-ready audit criteria.
- `get_sources()` — the provenance ledger for every source.

### Scanner tools (read-only)
- `audit_repo(path, pillars?, exclude?)` — evaluate every checklist criterion
  against a local repo; returns per-criterion results with **redacted** evidence.
- `audit_summary(path, pillars?, exclude?)` — scorecard summary only (no evidence).
- `generate_scorecard(path, pillars?, out_dir?, exclude?)` — per-pillar scorecard
  as JSON **and** Markdown; writes files when `out_dir` is given.

### Resources
- `sfi://skill` — this document.
- `sfi://knowledge/pillars` — raw pillars JSON.
- `sfi://knowledge/checklist` — raw checklist JSON.

## How to audit a project

1. **Scope.** Confirm the absolute path to the target repo. To focus, pass
   `pillars` (e.g. `"1,4"` or `"protect-networks"`). Exclude vendored or
   generated trees with `exclude` (e.g. `"vendor,third_party,dist"`).
2. **Scan.** Call `generate_scorecard(path, out_dir="reports")` (or run the
   harness — see below). This walks the repo read-only and evaluates all
   criteria.
3. **Read the scorecard.** Each criterion resolves to one of:
   - **`fail`** — an *anti-signal* matched (a likely violation). Highest priority.
   - **`pass`** — a positive *signal* matched and no anti-signal did (automated
     evidence the control is present; not a correctness guarantee).
   - **`manual`** — nothing matched; a human must verify. Common for tenant-,
     policy-, or platform-level controls that are invisible in source.
4. **Triage findings** by severity (`critical` > `high` > `medium` > `low`) and
   pillar. For each finding use the criterion's `how_to_verify` / remediation and
   `source_url`.
5. **Work the manual list.** `manual` items are *not* passes — walk them with the
   owner (e.g. Conditional Access, PIM, tenant inventory, SIEM coverage).
6. **Re-audit** after fixes and track the per-pillar score trend.

### Scoring
Per pillar and overall, score = `100 × earned / possible` over **determined**
criteria only (pass + fail); `manual` items are excluded from the denominator so
unknowns never inflate or deflate the grade. Severity weights: critical 5, high
3, medium 2, low 1. Grades: **A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F**. A pillar
with only manual items scores `N/A`.

## Running without an MCP client (harness)

The harness is a thin CLI over the same engine:

```bash
# Audit any project and write reports/<repo>-sfi-scorecard.{json,md}
python harness/run_audit.py /path/to/repo --out reports

# Limit to specific pillars and skip vendored code
python harness/run_audit.py /path/to/repo --pillars 1,4 --exclude vendor,dist

# Dogfood: audit THIS repository (excludes the KB and test fixtures)
python harness/run_audit.py --self --out reports
```

`run_audit.py` exits non-zero when any criterion fails, so it can gate CI. Golden
fixtures under `harness/fixtures/` (a compliant and a deliberately non-compliant
project, each with an `expected.json`) are asserted by the pytest suite in
`mcp_server/tests/` to keep audit logic correct as the KB is refreshed.

## Safety & limitations
- **Read-only.** The scanner never writes to the target and never transmits repo
  contents anywhere. Evidence snippets are **redacted** (secret-looking values
  masked) before being returned.
- **Heuristic, not certification.** A `pass` means automated evidence was found,
  not that the control is implemented correctly. A clean scorecard is a starting
  point for review, not a compliance attestation.
- **Source of truth.** Both this skill and the scanner read the same
  `data/*.json`, so guidance and automated checks never drift. To change what is
  audited, update the knowledge base (see `docs/PROVENANCE.md`) — never hard-code
  criteria in the scanner.

### How the scanner matches (so you can interpret results)
Knowing the mechanics prevents over-trusting a `pass` or a `manual`:
- **Content, not paths.** Signals match file **contents**, not file names or
  globs. A criterion is not satisfied by a file merely *existing* at a path — the
  distinguishing text must appear inside a scanned file. (KB tokens are therefore
  written as content markers, e.g. `resource "` rather than `**/*.tf`.)
- **Single-line, per-line matching.** Each token is tested against one line at a
  time; multi-line/blockwise constructs won't match across newlines.
- **Heuristic signals.** A `pass` is "evidence seen", a `fail` is "anti-pattern
  seen", and everything else is `manual` (undetermined) and **excluded from the
  score** — a high score with many `manual` criteria still needs human review.
- **Working tree, not history.** Structural checks (dependency pinning, CODEOWNERS,
  branch protection hints) inspect the files present on disk, not git history,
  branch-protection settings on the server, or CI runtime state.
- **Binary/large/vendored files skipped.** Non-text, oversized, symlinked, and
  ignored directories (`.git`, `node_modules`, `.venv`, …) are not scanned.
Treat the scorecard as triage: confirm each `pass` and resolve each `manual`
against the pillar guidance before drawing conclusions.
