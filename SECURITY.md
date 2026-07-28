# Security Policy

This repository contains the **SFI audit skill and MCP server** — a read-only
tool that audits other projects against Microsoft's Secure Future Initiative
(SFI). It stores no secrets and transmits no scanned content.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**. Do not open a public
issue for a security report.

- Preferred (private): use GitHub's **private vulnerability reporting**, which is
  enabled on this repository — go to the **Security** tab and choose
  **Report a vulnerability** (Security → Advisories → Report a vulnerability).
  This opens a private advisory visible only to you and the maintainer.
- Fallback: if you cannot use private reporting, open a public issue that
  contains **no vulnerability details** — just ask the maintainer
  [@Manaiakalani](https://github.com/Manaiakalani) to open a private channel,
  and share specifics only through the private advisory once it exists.

Include a description, reproduction steps, affected files/versions, and impact.
We aim to acknowledge within **2 business days** and to agree on a remediation
timeline within **5 business days**.

## Scope

In scope:

- The MCP server (`mcp_server/`), the audit harness (`harness/`), and the
  knowledge-base build (`scripts/build_kb.py`).
- Incorrect audit logic that could cause a project to pass a control it
  actually violates (false negatives), or that could leak secret material into
  audit evidence.

Out of scope:

- The intentionally insecure regression fixtures under
  `harness/fixtures/noncompliant/` (they contain deliberately planted, fake
  credentials used to test the scanner).

## Handling of scanned data

The scanner is **strictly read-only**: it never writes to the target repository
and never transmits repository contents off the machine. Evidence snippets are
redacted (secret-looking values are masked) before they are returned.
