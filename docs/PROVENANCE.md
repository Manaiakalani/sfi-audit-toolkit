# PROVENANCE & REFRESH

How the SFI knowledge base is versioned, how it was built, and the exact
procedure to refresh it when Microsoft updates SFI.

## Knowledge-base versioning

- The KB carries a semantic `version` (currently **1.0.0**) and a
  `generated_at` date, stamped into every `data/*.json` file by
  `scripts/build_kb.py`.
- **Bump rules:**
  - **patch** — wording, `how_to_verify`, or signal/anti-signal tuning with no
    change to which criteria exist.
  - **minor** — new criteria, objectives, patterns, or sources added.
  - **major** — pillars restructured, criterion IDs renamed/removed, or the
    schema changes (breaking consumers).
- Criterion IDs (`<pillar-slug>/<criterion-id>`) are a stable contract: the
  scorecard, tests, and any downstream tracking key off them. Prefer adding a new
  ID over silently repurposing an existing one.

## Source ledger

The full, machine-readable manifest is [`data/sources.json`](../data/sources.json)
(served by `get_sources`). Each entry records `url`, `title`, `type`,
`retrieved_at`, a `readable` flag, `used_for`, and a `report_version`. At v1.0.0
the ledger holds **29 sources** retrieved **2026-07-24** (this count includes the
durable Microsoft Learn pattern pages cited as checklist `source_url`s, so every
citation is traceable to a recorded source). See
[`SOURCES.md`](./SOURCES.md) for the human-readable list and the **PDF
readability caveat** (progress-report PDFs were not machine-parseable and were
sourced via their HTML equivalents).

## How v1.0.0 was built (multi-model orchestration)

The initial knowledge base was produced by four models working in parallel, each
writing a **disjoint** staging fragment (no write conflicts), then synthesized by
the build script. This record is kept for reproducibility and future refreshes.

| Model | Role | Produced |
| ----- | ---- | -------- |
| **gpt-5.6-sol** | Deep extraction, pillars 1–3 | `staging/pillars_1_3.json` |
| **gemini-3.1-pro** | Deep extraction, pillars 4–6 | `staging/pillars_4_6.json` |
| **mai-code-1-flash** | Bulk extraction | `staging/patterns.json`, `staging/sources_raw.json` |
| **opus-4.8** | Synthesis scaffold | `staging/principles.json`, `staging/schema.json` |
| **opus-4.6** | Audit & deploy | Code-reviewed the deliverable (found 4 real bugs, all fixed — see below); registered + verified the MCP server over stdio |
| **/rubber-duck** | Confirmation | Final logic/design pass |

Post-synthesis hardening (applied during the build/verify phase and captured in
the fixtures + tests):

- Removed over-broad anti-signals that caused false positives when a scanned
  repo happened to contain the vocabulary — e.g. bare `*`, `^`, `latest` in
  *trusted-dependencies*, and substring `MD5`/`DES` in *crypto-agile* (now
  word-boundary regexes `\bMD5\b`, `\bDES\b`). Literal matching is
  case-insensitive substring, so short/common tokens must be regex-anchored.
- Dropped a stray `cp1` token (the meaningful `xms_cc` claim already covers CAE
  capability).

**opus-4.6 audit round** (code review before deployment) found and fixed four
issues, each now covered by a regression test in `mcp_server/tests/test_scanner.py`:

1. *(critical)* The six wildcard IaC anti-signals written as `key: ['*']` were
   silently classified as regex **character classes** (`['*']` → "one of `'` or
   `*`") and never matched. Rewritten as explicit, case-insensitive regexes that
   match both Bicep (`actions: ['*']`) and ARM/JSON (`"actions": ["*"]`) forms,
   e.g. `(?i)\bactions['"]?\s*:\s*\[\s*['"]\*['"]\s*\]`.
2. *(medium)* `_requirements_unpinned` treated a `==` inside a PEP 508 environment
   marker (`requests ; python_version == "3.8"`) as a version pin and skipped the
   unpinned dependency. Now only the specifier before `;` is inspected.
3. *(medium)* Secret redaction thresholds were too high (12-char assigned / 8-char
   quoted), leaking short secrets into evidence snippets. Lowered to 6 for both —
   for a security tool the safe direction is to over-redact.
4. *(low)* The `print()` telemetry anti-signal matched substrings like
   `footprint()`/`sprint()`. Changed to a word-boundary regex `(?i)\bprint\(`.
   Because this made `print(` genuinely matchable, the self-audit excludes were
   widened to `scripts/` and `harness/` (CLI/dev tooling where `print()` is
   legitimate output, not a service telemetry gap).

**/rubber-duck confirmation round** (final logic/design pass, run as gpt-5.6-sol)
confirmed the scoring/status-precedence core is sound and surfaced further
hardening, each now covered by regression tests:

1. *(scanner integrity)* An unknown pillar filter (`audit_repo(path, pillars=["typo"])`)
   silently normalized to a non-existent slug, yielding **zero criteria** — a
   green "0 failed" audit of nothing. `_normalize_pillars` now raises
   `ValueError` listing the valid slugs; the MCP tools surface it as an error.
2. *(read-only guarantee)* `generate_scorecard` could write its JSON/Markdown
   **inside the repository being audited**, mutating the scanned tree. It now
   refuses to write at/under the audit root unless `allow_in_tree=True` (used
   only by the deliberate `--self --out reports` dogfood).
3. *(false PASS)* A malformed / non-object `package.json` (`[]`, `null`, invalid
   JSON) was counted as a usable manifest and could yield a false *pass* on
   dependency pinning. `_package_json_unpinned` now returns `None` for unusable
   manifests and the caller skips them (criterion stays *manual*).
4. *(evidence leak)* Redaction only masked quoted/assigned values, so a
   standalone token on its own line (AWS key, GitHub PAT, JWT, PEM header,
   `Bearer <token>`) could still surface in evidence. Added standalone
   secret-format patterns that mask these wherever they appear.
5. *(symlink boundary)* The walker could follow a symlink out of the repository.
   Symlinked files and directories are now skipped.
6. *(KB token hygiene)* Fixed a bracket-literal signal
   (`policyTypes: [Ingress, Egress]`, which was an unintended regex character
   class) to a precise `(?i)policytypes\s*:\s*\[[^\]]*egress`; removed three
   generic lone-word signals (`scope`, `owner`, `owners`) that could pass a
   criterion on unrelated prose; and converted four path/glob signals
   (`**/*.tf`, `**/*.bicep`, `.github/**/codeql.yml`, `.github/secret_scanning.yml`)
   — which never match because the scanner reads file **content**, not paths —
   into content markers (`resource "`, `Microsoft.Network/`, `github/codeql-action`,
   `detect-secrets`).
7. *(reproducibility)* `scripts/build_kb.py` now honors `SOURCE_DATE_EPOCH` for a
   deterministic `generated_at`, and stamps KB `version`/`generated_at` onto the
   principles and patterns documents.

**Round-2 multi-model audit** (gpt-5.6-terra scanner engine, gemini-3.1-pro
KB/docs, mai-code-1-flash tests/harness/deploy; triaged by the orchestrator and
verified against the Microsoft Learn SFI overview). Each fix below has a
regression test in `mcp_server/tests/test_scanner.py` under the round-2 section.

*Scanner engine (terra):*

1. *(blocking, boundary)* The walker only checked `is_symlink()`, so an **NTFS
   junction / reparse point** could redirect the scan outside the repository.
   `scanner.py` now skips reparse points (POSIX symlinks *and* Windows
   `FILE_ATTRIBUTE_REPARSE_POINT`) and enforces a `resolve().relative_to(root)`
   boundary on every file.
2. *(high, false PASS)* Absence-based structural checks read only the
   content-scanned file list, so an oversized (>1 MB) or binary tracked `.env`
   was invisible and passed. Presence checks now run over `all_paths` — every
   candidate file **name** regardless of size — and the scan surfaces a
   `truncated` flag when a cap stops the walk.
3. *(high, memory)* Structural hit-lists were capped only at return; they now
   cap **while accumulating** (`_MAX_STRUCT_HITS`).
4. *(high, false PASS)* Dependency pinning missed unpinned deps hidden behind pip
   `-r`/`-c` includes (silently skipped) and accepted npm partials (`"1"`,
   `"1.2"`) as pinned. Includes are now followed (cycle-guarded) and npm pins
   require **exact semver**; non-registry specs (git/url/file/link/workspace/npm:
   alias) are out of scope.
5. *(high, false PASS)* A quoted YAML key (`- "uses": actions/checkout@v4`) hid an
   unpinned action from `_USES_RE`; the pattern now allows optional quotes around
   the `uses` key.
6. *(high, evidence leak)* A bare 40-char AWS **secret** paired with an `AKIA…`
   access-key id (or an `aws … secret/access key` context) now gets redacted; the
   token is too generic to mask globally without an AWS signal on the line.
7. *(medium, bypass)* Excludes were case-sensitive and did not normalize `./` or
   backslashes, so an exclude could be bypassed on Windows. They are now
   casefolded and normalized on both sides.
8. *(medium, false PASS)* `CODEOWNERS`/`SECURITY.md` were honored **anywhere** in
   the tree; GitHub honors them only at the repo root, `.github/`, or `docs/`.
   Location is now enforced, and `CODEOWNERS` must contain an actual owner rule
   (an `@`-owner line), not just comments.
9. *(low, crash)* A non-ASCII "digit" pillar key (e.g. `²`) passed `str.isdigit()`
   but crashed `int()`; `_match_pillar` now guards with `isascii()`.
10. *(low, crash)* `generate_scorecard` did not catch `OSError` (e.g. `out_dir`
    is a file), so the MCP tool raised instead of returning a clean error. Fixed.

*Tests / harness / deploy (mai):*

- `harness/run_audit.py` now exits **2** with a stderr message (instead of a
  traceback) when a scorecard write is refused; the noncompliant golden fixture
  pins an **exact** failure count (8); and `scripts/register_mcp.ps1` was added as
  a **portable** launcher that resolves all paths relative to itself so the server
  can be registered from any checkout (the absolute paths in
  `~/.copilot/mcp-config.json` remain machine-local by design).

*Knowledge-base corrections (gemini + orchestrator):*

- **Pillar 6 NIST CSF functions** corrected from `RS, RC` to `ID, RC, RS, GV` to
  match the authoritative Learn per-pillar table (`skill.md` and the KB updated,
  KB rebuilt).
- `sources_raw.json` now includes the durable **overview** and **adoption** Learn
  URLs that the pillar/checklist criteria cite; `build_kb.py` emits sources in a
  **stable sorted order** and uses a committed `DEFAULT_GENERATED_AT` (still
  `SOURCE_DATE_EPOCH`-overridable) instead of the wall-clock date.
- *Rejection reversed in Round 11* (see the Round-11 note below): the claim that
  the security-principle labeling was wrong was **correct**, not a false positive.
  Re-checking Microsoft's overview "Security principles" section confirmed the
  three principles are *Secure by design / Secure by default / Secure operations*;
  *Innovate / Implement / Guide* are the verbs Microsoft lists under "We use these
  principles to:" and are now preserved in the KB as
  `security_principle_application`. The separate claim that pillar 2 should read
  "protect **production** tenants" remains **rejected** (the official name is
  "Protect tenants and isolate systems"). Older progress reports' empty
  `new_patterns` arrays are **correct** — the named Patterns & Practices catalog
  launched in 2025 — and `patterns.json._fetch_notes` now says so explicitly.

**Round-3 `/rubber-duck` confirmation** (gpt-5.6-sol reasoning over the round-2
changes; findings triaged by the orchestrator, each with a regression test in the
`test_scanner.py` round-3 section). These closed remaining *false-pass* and
*honesty* gaps the pass/fail verification gates did not surface:

1. *(blocking, honest reporting)* A **truncated scan** carried `scanned.truncated`
   in the raw JSON but the scorecard could still print an unqualified `A/100`. The
   scanner now does a **single walk** so `files ⊆ all_paths` always holds, and the
   scorecard exposes `overall.incomplete` plus a prominent **"Incomplete scan"**
   banner in Markdown; `audit_summary` returns the `scanned` block.
2. *(false PASS + robustness)* pip include-following now also handles the
   **attached** short form (`-rfile.txt`), flags **wildcard equality** (`==1.*`)
   as unpinned, records **unresolved includes** (missing/oversized/external) as
   `manual` rather than a silent pass, and is **iterative** so a deep `-r` chain
   cannot raise `RecursionError`.
3. *(false PASS)* `CODEOWNERS` selection now follows **GitHub precedence**
   (`.github/` > root > `docs/`), requires an owner token **after** the path
   pattern (an `@` inside the pattern no longer counts), and returns **`manual`**
   (not an automatic pass) when the file is too large/binary to read.
4. *(false NEGATIVE)* Flow-style actions (`- { uses: actions/x@v4 }`) are now
   detected by `_USES_RE`.
5. *(false POSITIVE + hardening)* npm exact-semver accepts full **prerelease +
   build** metadata (`1.2.3-rc.1+build.5`), uses ASCII `[0-9]` so full-width
   digits never count as a pin, and the dependency check enforces a **global**
   offender budget.
6. *(low, crash + determinism)* `_match_pillar` length-bounds a numeric key before
   `int()` (avoids Python's integer-string-conversion limit on a huge digit
   string), and `build_kb.py` writes the KB with **LF** bytes so it is
   byte-identical across operating systems.

**Round-4 `/rubber-duck` confirmation** (gpt-5.6-sol re-review of the round-3
changes; each finding carries a regression test in the `test_scanner.py` round-4
`rd8` section). The round-3 refactors were confirmed correct; these four residual
edge cases were closed:

1. *(false PASS)* A pip include that leaves the scanned set — external (`-r
   ../shared.txt`), absolute (`-r /etc/base.txt`), URL (`-r https://…`), or a
   **bare `-r`** with no argument — is now recorded as **unresolved** so the
   dependency check reports **`manual`**, never a silent clean pass.
2. *(bound + non-quadratic)* the unresolved-include list is **capped** at
   `_MAX_STRUCT_HITS` and guarded by a `queued` set, so a pathological
   requirements graph cannot grow it without bound or make membership checks
   quadratic.
3. *(false NEGATIVE)* a `uses` key that is **not first** in a flow mapping
   (`- { name: Checkout, uses: actions/x@v4 }`) is caught by a comma-anchored
   `_USES_FLOW_RE`; results are de-duplicated by `(line, ref)` so an action
   matched by both patterns is only reported once.
4. *(false PASS)* CODEOWNERS owner tokens are validated with strict
   `_OWNER_RE`/`_EMAIL_RE`, so a bare `@` (or other non-handle token) after the
   path pattern no longer counts as an owner.

**Round-5 `/rubber-duck` confirmation** (gpt-5.6-sol re-review of the round-4
changes; each finding carries a regression test in the `test_scanner.py` `rd9`
section). The round-4 fixes were confirmed correct; six deeper edge cases were
closed:

1. *(false PASS, robustness)* scanned files are now decoded as **`utf-8-sig`**,
   so a leading **UTF-8 BOM** can no longer hide a first-line `-r` include, a
   `uses:` key, or any other first-line signal.
2. *(false PASS, honesty)* a manifest or workflow that is **present but could not
   be read** (oversized, binary, or — for `package.json` — malformed/non-object)
   is now surfaced as **`manual`** instead of being silently ignored while a
   clean sibling yields a pass. This makes the dependency and Actions checks
   consistent with the CODEOWNERS "unreadable ⇒ manual" rule.
3. *(false NEGATIVE)* GitHub Actions detection is now **line-based**: it skips
   block-scalar (`run: |`) bodies, strips inline comments, and recognizes flow
   mappings only in real key position. This catches a `uses` in a **first-key
   flow mapping** (`call: { uses: … }`) and a **flow sequence**
   (`steps: [{ uses: … }]`) that the previous regexes missed.
4. *(false POSITIVE)* the same line-based scan means JSON embedded in a `run:`
   shell string (`echo '{"uses":"x@v1"}'`) and a `uses` inside a comment no
   longer produce a phantom unpinned-action finding — all without adding a YAML
   parser dependency to a security tool.
5. *(false PASS)* an owner hidden behind an **inline comment** (`* # @team`) no
   longer counts: `_has_owner_rule` stops at the first `#` token.
6. *(grammar, false FAIL + false PASS)* `_OWNER_RE`/`_EMAIL_RE` were tightened to
   accept **Enterprise Managed User** handles (an internal `_`, e.g.
   `@mona-cat_contoso`) while rejecting edge-invalid tokens (`@owner-`, `@org/.`,
   `a@b..com`).

**Round-6 `/rubber-duck` confirmation** (gpt-5.6-sol re-review of the round-5
changes; each finding carries a regression test in the `test_scanner.py` `rd10`
section). The round-5 fixes were confirmed correct; six finer edge cases were
closed, and the fragile flow-detection regexes were replaced by a small
quote-aware line tokenizer that resolves several of them at the root:

1. *(false PASS, blocking)* CODEOWNERS matching is now **case-sensitive** at the
   exact name and directory. GitHub honors a code-owners file **only** as
   `CODEOWNERS` in the repo root, `.github/`, or `docs/` — regardless of the
   host OS's case-folding — so a mis-cased `codeowners`/`.GitHub/CODEOWNERS` no
   longer produces a false pass on `require-code-owner-review`. `SECURITY.md`
   detection stays case-insensitive (GitHub is lenient there), avoiding a false
   fail.
2. *(false PASS, blocking)* action detection is now driven by a **quote-aware
   tokenizer** (`_line_uses_refs`) instead of comment-stripping + flow regexes.
   A `#` inside a quoted scalar (`- { name: "Build #1", uses: … }`) no longer
   truncates the line before a real `uses:`, so the unpinned action is caught.
3. *(false NEGATIVE)* the same tokenizer recognizes a `uses` in a **bracketless
   flow-sequence mapping** (`steps: [uses: …]`) and behind a **YAML anchor node
   property** (`- &checkout { uses: … }`) — both of which the anchored flow
   regexes missed.
4. *(false POSITIVE)* the tokenizer skips **quoted `run:` values** in flow form
   (`- { run: 'echo {"uses":"x@v1"}' }`), so embedded JSON no longer produces a
   phantom unpinned-action finding.
5. *(false POSITIVE)* `_BLOCK_SCALAR_RE` now accepts an **indentation and
   chomping indicator in either legal order plus a trailing comment**
   (`run: |2-`, `run: >2+`, `run: | # note`), so those block-scalar bodies stay
   skipped rather than being scanned as YAML.
6. *(false PASS)* `_OWNER_RE`/`_EMAIL_RE` reject **impossible handles and
   emails** — consecutive or edge hyphens (`@mona--cat`) and empty domain labels
   (`user@foo..example.com`) — while still accepting real handles, `@org/team`
   slugs, and EMU `_shortcode` suffixes.

One theoretical item (rejecting punycode `xn--` domains) was reviewed and
**deliberately not changed**: honoring it correctly needs IDNA normalization, a
disproportionate dependency for a rare CODEOWNERS email form. A `with:` input
literally named `uses` remains a possible (extremely rare) false positive; this
matches the pre-existing behavior and is documented as a known limitation.

**Round-7 `/rubber-duck` confirmation** (gpt-5.6-sol re-review of the round-6
changes; each fix carries a regression test in the `test_scanner.py` `rd11`
section). The round-6 case-sensitivity, block-indicator, and owner-grammar fixes
were confirmed correct. The reviewer showed that the *char-class* action
tokenizer still mis-modeled YAML scalars, so it was **replaced by a small
value-aware line scanner** (`_read_scalar` / `_is_map_colon` / `_is_comment_at`
/ `_skip_value_props` driving a rewritten `_line_uses_refs`). The scanner tracks
flow depth, mapping-key position, quotes, node properties, and — crucially — the
YAML rule that **`#` starts a comment only after whitespace**. This closes a
family of related defects at the root:

1. *(false PASS)* an unquoted `#` inside a value — a step `name: Build#1`, or a
   ref written as `…@<sha>#mutable` — no longer truncates the line before, or at,
   a real `uses:`. The complete scalar is read, so the unpinned/mutable action is
   correctly flagged.
2. *(false PASS)* an apostrophe or quote in the *interior* of a plain value
   (`name: don't`) is treated as literal text, not a string delimiter, so a
   following `uses:` in the same flow map is still detected.
3. *(false PASS)* block-scalar detection now fires **only as the actual mapping
   value** (`key: |`/`>` at value position, outside flow). A plain value that
   merely ends in `:|` (e.g. `name: foo:|`) no longer opens a spurious skip that
   would swallow the next line's `uses:`. Value-side anchors are handled too, so
   `run: &script |` is recognized as a block header.
4. *(false FAIL)* `-`, `{`, `[`, `,` and quotes are structural only at token
   boundaries / in flow context, so a `uses:` substring inside a `run:` command
   (`run: echo --uses:actions/x@v4`) no longer produces a phantom action, and a
   value-side anchor before a pinned ref (`uses: &checkout actions/x@<sha>`)
   correctly reads as pinned.
5. *(false PASS)* `_EMAIL_RE`'s local part is now a dot-atom, rejecting
   consecutive or edge dots (`a..b@example.com`) while still accepting normal
   addresses such as `first.last+tag@example.com`.

**Accepted limitations (deliberately not handled — a zero-dependency line scanner
trades total YAML fidelity for having no parser or network dependency in a
security tool):**

- A mapping key written with character escapes — e.g. `"us\u0065s":` — is not
  decoded, so an action hidden behind an escaped `uses` key would be missed. This
  is deliberate obfuscation, not a realistic authoring mistake, and if an
  attacker controls the workflow, pinning is already moot.
- Backslash/`\x`/`\u` escapes *inside a quoted `uses` value* (e.g. a SHA written
  as `"…@\x30…"`) are not un-escaped, so such a ref may be reported as unpinned.
  No real workflow writes a SHA with escapes.
- A YAML **flow mapping split across multiple physical lines** is scanned
  line-by-line; a `uses:` that begins on one line and completes on the next is a
  known non-goal.
- The total length of an Enterprise Managed User handle (base + `_shortcode`)
  is not capped at 39; only the documented per-segment grammar is enforced, to
  avoid falsely rejecting long-but-legitimate EMU handles.

These are recorded here so a future refresh can revisit them (for instance, if
the tool ever takes on an optional YAML parser) with full context.

**Round-8 `/rubber-duck` confirmation** (gpt-5.6-sol re-review of the value-aware
scanner; each fix carries a regression test in the `test_scanner.py` `rd12`
section). The scanner was confirmed sound for ordinary block and spaced-flow
workflows; four gaps in **compact / JSON-style flow** were closed:

1. *(false PASS)* a compact JSON-style flow mapping `{"uses":"actions/x@v4"}`
   (a `:` with no following space after a quoted key) is now recognized:
   `_is_map_colon` treats a `:` inside flow as a separator when it is directly
   followed by a flow terminator/collection or a quoted scalar. The unpinned
   action is caught instead of being silently missed.
2. *(false FAIL)* the same rule keeps a compact nested flow value
   (`{with:{fetch-depth: 0}, uses: actions/x@<sha>}`) from corrupting flow depth,
   so the trailing `}` is no longer glued onto the SHA.
3. *(false FAIL)* a YAML **alias** used as a value (`uses: *checkout`, reusing an
   earlier `uses: &checkout actions/x@<sha>`) is skipped rather than scored as an
   unpinned ref — its pin-state is already judged at the `&checkout` anchor
   definition, so nothing is lost.
4. *(false FAIL)* the version is now split on the **last** `@`
   (`rsplit("@", 1)`), so a reusable-workflow path that itself contains `@`
   (`acme/ci/.github/workflows/build@v2.yml@<sha>`) is pinned correctly.

At this point the action scanner is correct for all realistic single-line
workflow YAML (block, spaced-flow, compact/JSON-flow, anchors, aliases, comments,
block scalars, docker/local refs, and multi-`@` paths). The remaining residuals
are the accepted limitations listed above (multi-line flow mappings and
character-escaped keys/values), which are out of scope for a deliberately
parser-free scanner.

**Round-9 `/rubber-duck` confirmation** (gpt-5.6-sol, scoped to realistic
*blocking false-PASSes* only). Two remaining single-line gaps were closed, each
with an `rd13` regression test:

1. *(false PASS)* a compact quoted-key mapping with a **plain** (unquoted) value,
   `{"uses":actions/checkout@v4}`, was missed because a `:` with no following
   space after a quoted key was not treated as a separator. A `:` after a quoted
   key inside a flow collection is now always a mapping separator, so the unpinned
   ref is caught.
2. *(false PASS)* the Round-8 alias handling assumed an alias was "already scored
   at its anchor definition" — true only when the anchor sits on a `uses:` value.
   An anchor placed on a **non-`uses`** key and then smuggled into `uses:` via an
   alias (`{name: &ref actions/checkout@v4, uses: *ref}`) escaped scoring
   entirely. Aliases are now **resolved** against `uses:` anchors collected across
   the whole file: `uses: *checkout` reuses the value defined at
   `uses: &checkout …` (so legitimate DRY reuse of a *pinned* action still passes,
   in both block and flow form), while an alias that resolves to no known `uses:`
   anchor — or a dangling alias — is reported verbatim (`*name`) and classified
   **unpinned** rather than silently skipped. A mutable ref reachable only through
   an alias can no longer score as pinned.

This closes the multi-round rubber-duck loop (rounds 3–9): the action scanner has
no remaining known false-PASS for realistic single-line workflow YAML, and the
only residuals are the explicitly accepted parser-fidelity limitations above
(multi-line flow mappings; character-escaped keys/values), which by design are
out of scope for a zero-dependency line scanner.

**Round-10 `/rubber-duck` confirmation** (gpt-5.6-sol, re-review of the new
alias-resolution code). No blocking false-PASS was found — the security-critical
guarantee (a mutable ref can never score pinned) held. One *non-blocking
false-FAIL* was closed with an `rd14` regression test:

* *(false FAIL)* a pinned action reference centralised in a non-`uses` mapping
  value — e.g. `env: {CHECKOUT: &checkout actions/checkout@<sha>}` — and reused
  via `uses: *checkout` failed, because Round-9 only collected anchors from
  `uses:` values. Anchor collection is now generalised to **any** mapping value,
  so the alias resolves to the pinned SHA and passes. The false-PASS guard is
  preserved: a *mutable* ref anchored anywhere still resolves to a FAIL when
  aliased into `uses:`, and a dangling alias remains conservatively unpinned.

This closes the multi-round rubber-duck loop (rounds 3–10): the action scanner has
no remaining known false-PASS for realistic single-line workflow YAML — and no
known false-FAIL either — with the only residuals being the explicitly accepted
parser-fidelity limitations above (multi-line flow mappings; character-escaped
keys/values), which by design are out of scope for a zero-dependency line scanner.

**Round-11 multi-model audit + `/rubber-duck` confirmation** (gpt-5.6-sol,
gemini-3.1-pro, opus-4.8, mai-code-1-flash; deployed by opus-4.6). This round
widened scope beyond the action scanner to redaction, the file-walk engine,
dependency/env structural checks, scoring, and knowledge-base accuracy. Each fix
carries a regression test in the round-11 sections of `test_scanner.py` /
`test_knowledge.py`.

*Redaction hardening (`matching.py`):*
1. *(leak)* Key-aware masking now covers secret **values the generic matchers
   missed**: XML secret elements (`<clientSecret>…</clientSecret>`), Windows
   `setx NAME value`, unquoted/short values after a secret key (`pwd=abc`), and
   multi-word values (`clientSecret: my long phrase`). The value is masked to end
   of line, so a value containing `#` cannot leak a trailing fragment.
2. *(leak)* A PEM private key **flattened onto one physical line** (literal `\n`
   separators) is redacted through the end of the line, not just its header.
3. *(leak)* `Bearer` tokens containing standard-base64 characters (`/ + =`) are
   fully masked (previously the value class stopped at the first `/`).
4. *(robustness)* The two quoted-value branches were made **disjoint** so a crafted
   run of backslashes cannot backtrack catastrophically; redaction input is capped
   at 2 000 chars and regex signal search at 20 000 chars per physical line
   (dropped content is never displayed, so it cannot leak).

*File-walk engine (`scanner.py`):*
5. *(coverage gap)* An oversized or unreadable **text** file is now surfaced as an
   incomplete scan (`truncated` + a new `files_skipped` count) instead of being
   skipped silently, so an absence-based `pass` is never based on unscanned text.
   Genuinely binary files stay out of scope and do not flip the flag.

*Structural checks (`checks/structural.py`):*
6. *(false PASS, blocking)* Dependency pinning now detects **split requirements
   layouts** — `requirements/*.txt` and suffix-named `*requirements.txt`
   (`dev-requirements.txt`) — which the `requirements*.txt`-only matcher missed, so
   a project using them can no longer score a clean pass while shipping unpinned
   dependencies.
7. *(false PASS + false FAIL)* The tracked-`.env` allow-list is now matched on
   **exact dotted segments**, so a real `.env.distprod` is flagged (the `dist`
   token no longer excuses it) while `.env.tmpl`/`.env.tpl` templates are allowed.
8. *(false FAIL)* An npm version with a leading `v` (`v1.2.3`, `=v1.2.3`) is
   recognised as an exact pin (node-semver tolerates the prefix).

*Scoring / plumbing (`report.py`, `knowledge.py`, `server.py`):*
9. Scores never round to a **misleading extreme** — a result stays at 99 while any
   weight is unearned and at 1 while any weight is earned, so a lone failure can
   never display as 100. `clear_cache` dropped a dead no-op, the `audit_repo`
   docstring was corrected (relative paths resolve; `;` separators accepted), and
   the scanner tools now also catch `KnowledgeBaseError`.

*Knowledge-base accuracy (via `staging/` + rebuild):*
10. **Security principles relabeled (g1):** the KB now names Microsoft's three
    principles — *Secure by design / default / operations* — and preserves
    *Innovate / Implement / Guide* as `security_principle_application`. This
    **reverses** the earlier Round-2 "rejection" recorded in the Source-manifest
    note above, on the evidence of the overview's "Security principles" section.
11. **Provenance ledger completed (g2/g3):** the seven durable Learn pattern pages
    that checklist criteria cite were added to `sources_raw.json`, so **every**
    checklist `source_url` now resolves in the ledger (asserted by a new test). The
    ledger count is now **29** (README/PROVENANCE corrected from the stale "20").

**Accepted limitations (Round 11, deliberately not fixed):**
- A pip requirements file that pins versions **only via a `-c constraints.txt`**
  include (no `==` on the requirement line itself) is still reported as unpinned.
  Suppressing it risks a worse false-PASS, the pattern is uncommon, and the current
  behaviour matches common scanners that encourage explicit pins.
- Regex signal/anti-signal matching is bounded to the first 20 000 characters of a
  single physical line (redaction to 2 000). Real markers occur near line starts,
  so this only affects pathologically long minified lines.

## Refresh runbook

Run this whenever Microsoft publishes new SFI guidance or a new progress report.

1. **Re-extract** from the durable pages (see `SOURCES.md`) into `staging/`,
   keeping the same fragment ownership:
   - pillars 1–3 → `staging/pillars_1_3.json`
   - pillars 4–6 → `staging/pillars_4_6.json`
   - patterns + reports + raw source list → `staging/patterns.json`,
     `staging/sources_raw.json`
   - principles / ZT / NIST glossaries + schema → `staging/principles.json`,
     `staging/schema.json`
   Update each touched source's `retrieved_at` and, for reports, `report_version`.
2. **Rebuild:** `python scripts/build_kb.py`. Review the printed counts and any
   warnings.
3. **Diff** `data/*.json` against the previous version. Confirm every change is
   intended; watch for renamed/removed criterion IDs.
4. **Validate:** `python -m pytest mcp_server/tests -q`. The golden fixtures under
   `harness/fixtures/` assert the scanner still flags planted violations and
   passes the compliant sample. Fix the KB (not the tests) if a real regression
   appears; update fixtures only when the intended behavior genuinely changed.
5. **Guard against false positives:** run `python harness/run_audit.py --self`
   and confirm the tool still audits its own repo cleanly (no self-matches from
   new vocabulary). Add excludes or anchor patterns as needed.
6. **Bump** the `version` in `scripts/build_kb.py`, rebuild, and note the change.
7. **Re-deploy** if the running MCP server pins a data directory — the server
   reads `data/` live, so most refreshes need only a server restart.

## Integrity guarantees

- **Single source of truth.** `skill.md` guidance and the scanner both read
  `data/*.json`; there is no second copy of the criteria to drift.
- **Reproducible.** `build_kb.py` uses only the Python standard library and is
  deterministic given the same `staging/` inputs.
- **Read-only & redacting.** The scanner never writes to a target repo, never
  transmits its contents, and masks secret-looking values in evidence.
