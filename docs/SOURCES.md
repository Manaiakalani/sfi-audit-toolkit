# SOURCES — How we pull the SFI pillars

This document records **exactly how the SFI knowledge base is sourced** so the
audit requirements can be re-derived and updated over time. The machine-readable
ledger is [`data/sources.json`](../data/sources.json) (also served by the
`get_sources` MCP tool); this file is the human-facing runbook.

## Principles

1. **Durable pages first.** The pillar definitions, objectives, and mappings are
   extracted from the evergreen Microsoft Learn pages, which are updated in place
   as SFI evolves. Point-in-time progress reports are used for *deltas* and
   context, not as the primary schema.
2. **Everything is attributed.** Every pillar, objective, best practice, and
   audit criterion carries a `source_url`. Every source carries a
   `retrieved_at` date and a `readable` flag.
3. **Reproducible build.** Sources are extracted into `staging/`, then
   `scripts/build_kb.py` deterministically synthesizes `data/*.json`. Re-running
   the build from the same staging inputs yields the same knowledge base.

## Primary sources (durable)

| Source | Used for |
| ------ | -------- |
| Learn — [Secure Future Initiative overview](https://learn.microsoft.com/en-us/security/zero-trust/sfi/secure-future-initiative-overview) | The six pillars, the three security principles (secure by design / default / operations), Zero Trust framing |
| Learn — [What's new in SFI](https://learn.microsoft.com/en-us/security/zero-trust/sfi/secure-future-initiative-whats-new) | Newly introduced patterns, platform updates, progress deltas |
| Learn — [SFI adoption](https://learn.microsoft.com/en-us/security/zero-trust/sfi/secure-future-initiative-adoption) | Adoption best-practice tables → auditable criteria |
| Learn — per-pattern SFI pages (e.g. [phishing-resistant MFA](https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-mfa), [network isolation](https://learn.microsoft.com/en-us/security/zero-trust/sfi/network-isolation), [secure all tenants](https://learn.microsoft.com/en-us/security/zero-trust/sfi/secure-all-tenants-resources)) | The durable `source_url` each audit criterion cites; every one is recorded in the ledger |
| Trust Center — [Patterns and practices](https://www.microsoft.com/en-us/trust-center/security/secure-future-initiative/patterns-and-practices) | Pattern catalog, including AI/agentic patterns |

## Progress reports (context / deltas)

Landing pages (HTML, readable) and their PDF reports (see the note below):

- SFI Progress Report **July 2026** — trust-center page + PDF.
- SFI Progress Report **November 2025** — trust-center page + executive-summary PDF.
- SFI Progress Report **April 2025** — PDF.
- SFI Progress Report **September 2024** — PDF.

> **PDF note.** The progress-report **PDFs are not reliably machine-readable**
> through automated fetching (they returned no usable text at build time). Their
> substance was therefore sourced from the corresponding **HTML** trust-center
> pages and the Learn *what's-new* summaries instead. The PDFs remain in the
> ledger with `readable: false` for traceability. If you refresh and a PDF is
> parseable, set `readable: true` and record what you extracted.

## Extraction procedure

For each durable page:

1. Fetch the page and read the pillar/objective/pattern content.
2. Map each pillar to its **slug**, **Zero Trust** application, and **NIST CSF
   2.0** functions (GV, ID, PR, DE, RS, RC).
3. Turn each adoption best practice into one or more **audit criteria** with a
   `requirement`, `rationale`, `how_to_verify`, `severity`, and — critically —
   machine-detectable `signals` / `anti_signals` (literal tokens and/or
   regexes) plus the `source_url`.
4. Write the result to the appropriate `staging/*.json` fragment.
5. Run `python scripts/build_kb.py` and review the printed counts and warnings.

The step-by-step **refresh** procedure (including versioning and validation)
lives in [`PROVENANCE.md`](./PROVENANCE.md).
