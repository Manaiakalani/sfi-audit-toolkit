"""Structural SFI checks that are hard to express as simple signal patterns.

Each check reads the already-collected repository files and returns a result in
the same shape the scanner produces, so they merge seamlessly into the audit.
These checks are deterministic (high confidence).
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ADOPTION_URL = (
    "https://learn.microsoft.com/en-us/security/zero-trust/sfi/"
    "secure-future-initiative-adoption"
)

Files = List[Tuple[str, str]]

_DOTENV_ALLOW = ("example", "sample", "template", "tmpl", "tpl", "dist", "defaults", "schema")
# GitHub Actions are detected by ``_line_uses_refs`` — a small value-aware YAML
# line scanner — instead of by matching raw text. Tracking flow depth, mapping-
# key position, quotes, comments and node properties means a ``uses`` token, a
# ``#``, or a quote that appears *inside* a scalar value (JSON in a ``run:``
# command, a step ``name: Build#1``, a contraction like ``don't``) is never
# mistaken for a mapping key, a comment, or a string delimiter.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# Exact npm/semver pin: MAJOR.MINOR.PATCH with an optional -prerelease and/or
# +build metadata (ASCII digits only, so full-width/Unicode digits never count).
_EXACT_SEMVER = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$"
)
# GitHub honors CODEOWNERS / SECURITY.md only at the repo root, .github/, or docs/.
_RECOGNIZED_DIRS = ("", ".github", "docs")
# A valid CODEOWNERS owner token: an ``@user``/``@org/team`` handle or an email.
# A GitHub handle is 1-39 chars, alphanumeric with single *internal* hyphens (no
# leading/trailing/consecutive hyphen); an Enterprise Managed User adds a
# ``_shortcode`` suffix. A team slug allows internal ``.``/``_``/``-``. Emails
# require non-empty dot-separated domain labels and an alphabetic TLD.
_OWNER_RE = re.compile(
    r"^@[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}"
    r"(?:_[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38})?"
    r"(?:/[A-Za-z0-9](?:[._-]?[A-Za-z0-9])*)?$"
)
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
# Cap accumulated structural offenders so a pathological repo cannot blow up memory.
_MAX_STRUCT_HITS = 25


def _result(
    check_id: str,
    pillar_id: int,
    pillar_slug: str,
    requirement: str,
    severity: str,
    status: str,
    how_to_verify: str,
    signal_hits: Optional[List[Dict[str, Any]]] = None,
    anti_signal_hits: Optional[List[Dict[str, Any]]] = None,
    note: str = "",
) -> Dict[str, Any]:
    return {
        "id": check_id,
        "pillar_id": pillar_id,
        "pillar_slug": pillar_slug,
        "requirement": requirement,
        "severity": severity,
        "how_to_verify": how_to_verify,
        "source_url": ADOPTION_URL,
        "status": status,
        "confidence": "high",
        "signal_hits": signal_hits or [],
        "anti_signal_hits": anti_signal_hits or [],
        "note": note,
        "structural": True,
    }


def _hit(pattern: str, file: str, line: int = 0, snippet: str = "") -> Dict[str, Any]:
    return {"pattern": pattern, "mode": "structural", "file": file, "line": line, "snippet": snippet}


def _basename(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


def _dirname(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def check_tracked_env_files(root: Path, files: Files, all_paths: Sequence[str]) -> Dict[str, Any]:
    offenders = []
    allow = set(_DOTENV_ALLOW)
    for rel in all_paths:
        base = _basename(rel).lower()
        # Match the ``.env.<segment>`` suffix segments *exactly* against the
        # allow-list rather than as substrings, so a real ``.env.distprod`` is
        # not excused by the ``dist`` allow token (a false pass) while a
        # ``.env.tmpl`` template is still excused (not a false fail).
        if base == ".env" or (
            base.startswith(".env.") and not (set(base.split(".")[2:]) & allow)
        ):
            offenders.append(_hit("committed .env file", rel))
            if len(offenders) >= _MAX_STRUCT_HITS:
                break
    status = "fail" if offenders else "pass"
    return _result(
        "protect-identities-and-secrets/no-tracked-env-files",
        1,
        "protect-identities-and-secrets",
        "Real environment/secret files (.env) must not be committed to the repository; "
        "only redacted .env.example/.env.template files belong in source control.",
        "critical",
        status,
        "List working-tree files named .env or .env.<env> (excluding *.example/*.template) "
        "and confirm none contain live secrets; ensure .env is in .gitignore.",
        signal_hits=[] if offenders else [_hit("no committed .env files found", "")],
        anti_signal_hits=offenders,
        note="" if offenders else "No committed .env files detected.",
    )


def _present_but_unreadable(
    all_paths: Sequence[str], readable: Dict[str, str], match: Any
) -> List[str]:
    """Paths that exist in the repo and match ``match(rel)`` but whose contents
    were not available to scan (oversized, binary, or unreadable). A check must
    surface these instead of silently treating the repository as compliant."""
    out: List[str] = []
    for rel in all_paths:
        if rel not in readable and match(rel):
            out.append(rel)
            if len(out) >= _MAX_STRUCT_HITS:
                break
    return out


def _skip_quoted(line: str, i: int) -> int:
    """Return the index just past a single- or double-quoted scalar starting at
    ``line[i]``, honoring ``''`` inside single quotes and ``\\"`` inside double
    quotes. An unterminated quote consumes the rest of the line."""
    q = line[i]
    i += 1
    n = len(line)
    while i < n:
        c = line[i]
        if c == "\\" and q == '"':
            i += 2
            continue
        if c == q:
            if q == "'" and i + 1 < n and line[i + 1] == "'":
                i += 2  # doubled '' is an escaped single quote
                continue
            return i + 1
        i += 1
    return n


def _is_comment_at(line: str, i: int) -> bool:
    """A ``#`` starts a comment only at the start of the line or after
    whitespace; anywhere else it is an ordinary plain-scalar character (so a step
    ``name: Build#1`` or a ref ``…@sha#x`` is not truncated)."""
    return i < len(line) and line[i] == "#" and (i == 0 or line[i - 1] in " \t")


def _is_map_colon(line: str, i: int, n: int, flow: int) -> bool:
    """True if ``line[i]`` is a mapping ``key: value`` separator. Normally a ``:``
    must be followed by whitespace or end-of-line; inside a flow collection it may
    also be followed directly by a flow terminator/collection or a quoted
    (JSON-style) scalar, e.g. ``{"uses":"actions/checkout@v4"}`` or
    ``{with:{fetch-depth: 0}, uses: x}``."""
    if i >= n or line[i] != ":":
        return False
    if i + 1 >= n or line[i + 1] in " \t":
        return True
    return bool(flow) and line[i + 1] in ",}]{[\"'"


def _skip_value_props(line: str, i: int, n: int):
    """Skip whitespace and any value-side node properties — an anchor ``&name``
    or a tag ``!tag`` — so the underlying scalar (e.g. ``uses: &x actions/y@sha``)
    can be read. Return ``(index, anchor_name)`` where ``anchor_name`` is the name
    of the first ``&`` anchor seen (or ``None``); this lets a later YAML alias
    ``uses: *x`` be resolved back to the value it reuses."""
    anchor = None
    while i < n and line[i] in " \t":
        i += 1
    while i < n and line[i] in "&!":
        prop = line[i]
        j = i + 1
        while j < n and line[j] not in " \t":
            j += 1
        if prop == "&" and anchor is None:
            anchor = line[i + 1 : j]
        while j < n and line[j] in " \t":
            j += 1
        i = j
    return i, anchor


def _read_scalar(line: str, i: int, n: int, flow: int):
    """Read a plain or quoted scalar starting at ``line[i]`` and return
    ``(text, end)``. A quoted scalar is returned without its surrounding quotes;
    a plain scalar runs until a comment, a mapping ``:`` separator, end-of-line,
    or — inside flow — a ``,``/``}``/``]``. A quote or ``#`` in the *interior* of
    a plain scalar is literal, never a delimiter or comment."""
    if line[i] in "\"'":
        end = _skip_quoted(line, i)
        return line[i + 1 : end - 1], end
    k = i
    while k < n:
        c = line[k]
        if c == "#" and k > i and line[k - 1] in " \t":
            break
        if _is_map_colon(line, k, n, flow):
            break
        if flow and c in ",}]":
            break
        k += 1
    return line[i:k].rstrip(), k


def _line_uses_refs(line: str):
    """Scan one YAML line and return ``(nodes, opens_block)``. ``nodes`` is a list
    describing each ``uses:`` value on the line, in order, as a tuple:

    * ``("ref", value, anchor)`` — a literal action reference; ``anchor`` is the
      name of a value-side ``&anchor`` if one was attached (else ``None``);
    * ``("alias", name, None)`` — a YAML alias ``uses: *name`` that reuses the
      value defined at ``&name`` elsewhere in the file.

    ``opens_block`` reports whether the line opens a block scalar (``key: |``/``>``
    …) whose indented body must be skipped. The scanner tracks flow depth,
    mapping-key position, quotes, comments and node properties, so scalar
    *content* is never read as structure — this is what keeps a ``uses`` inside a
    ``run:`` command, or a ``#``/quote inside a name, from producing a phantom or
    missing action reference."""
    nodes: List[tuple] = []
    n = len(line)
    i = 0
    flow = 0
    while i < n:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n or _is_comment_at(line, i):
            break
        c = line[i]
        if flow == 0 and c == "-" and (i + 1 >= n or line[i + 1] in " \t"):
            i += 1  # block-sequence entry marker
            continue
        if c in "{[":
            flow += 1
            i += 1
            continue
        if c in "}]":
            flow = max(0, flow - 1)
            i += 1
            continue
        if c == ",":
            i += 1
            continue
        if c in "&!":  # node property (anchor/tag) at key position: skip its token
            i += 1
            while i < n and line[i] not in " \t":
                i += 1
            continue
        if _is_map_colon(line, i, n, flow):
            i += 1  # a value with no explicit key; skip the separator
            continue
        keystart = i
        key, i = _read_scalar(line, i, n, flow)  # a node begins: read key/scalar
        key_quoted = line[keystart] in "\"'"
        j = i
        while j < n and line[j] in " \t":
            j += 1
        # A ``:`` after a *quoted* key inside flow is always a mapping separator,
        # even when a plain value follows with no space — e.g. the compact form
        # ``{"uses":actions/checkout@v4}``.
        if not (
            _is_map_colon(line, j, n, flow)
            or (flow and key_quoted and j < n and line[j] == ":")
        ):
            continue  # a standalone scalar, not a mapping key
        vstart, vanchor = _skip_value_props(line, j + 1, n)
        if flow == 0 and vstart < n and line[vstart] in "|>":
            k = vstart + 1
            while k < n and line[k] in "+-0123456789":
                k += 1
            while k < n and line[k] in " \t":
                k += 1
            if k >= n or _is_comment_at(line, k):
                return nodes, True  # block-scalar header: skip its indented body
        if vstart < n and line[vstart] in "{[":
            i = vstart  # value is a nested flow collection; keep scanning into it
            continue
        if vstart < n and line[vstart] == "*":  # a YAML alias (*anchor)
            a = vstart + 1
            while a < n and line[a] not in " \t,{}[]":
                a += 1
            if key == "uses":
                nodes.append(("alias", line[vstart + 1 : a], None))
            i = a
            continue
        if vstart >= n or _is_comment_at(line, vstart):
            i = vstart
            continue  # empty value (e.g. ``uses:`` with nothing after it)
        value, i = _read_scalar(line, vstart, n, flow)
        if value:
            if vanchor:  # remember &anchor -> value so a later *alias can resolve it
                nodes.append(("anchor", vanchor, value))
            if key == "uses":
                nodes.append(("ref", value, None))
    return nodes, False


def _iter_action_refs(text: str):
    """Yield ``(line_no, ref)`` for each ``uses:`` action reference in a
    workflow, skipping block-scalar (``run: |`` ...) bodies so that neither shell
    text nor JSON inside a ``run`` string is mistaken for a ``uses`` mapping.

    A ``uses:`` value written as a YAML alias (``uses: *checkout``) is resolved
    back to the value it reuses, using ``&anchor`` definitions collected from
    *any* mapping value across the whole file (e.g. a pinned ref centralised in a
    top-level ``env:`` and reused via an alias). An alias that resolves to no
    known anchor — or a dangling alias — is reported verbatim (``*name``) so it is
    classified as *unpinned* rather than silently skipped: a mutable ref reachable
    only through an alias must never score as pinned."""
    anchors: Dict[str, str] = {}
    events: List[tuple] = []  # (line_no, kind, payload)
    block_indent = None
    for line_no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue  # blank line or still inside the block-scalar body
            block_indent = None  # dedented back out; process this line normally
        if not stripped or stripped.startswith("#"):
            continue
        nodes, opens_block = _line_uses_refs(raw)
        for kind, a, b in nodes:
            if kind == "anchor":
                anchors[a] = b  # a = anchor name, b = its scalar value
            elif kind == "ref":
                events.append((line_no, "ref", a))  # a = uses value
            else:  # alias
                events.append((line_no, "alias", a))  # a = alias name
        if opens_block:
            block_indent = indent
    seen_by_line: Dict[int, set] = {}
    for line_no, kind, payload in events:
        ref = payload if kind == "ref" else anchors.get(payload, "*" + payload)
        seen = seen_by_line.setdefault(line_no, set())
        if ref in seen:
            continue
        seen.add(ref)
        yield line_no, ref


def check_actions_pinned(root: Path, files: Files, all_paths: Sequence[str]) -> Dict[str, Any]:
    def _is_workflow(rel: str) -> bool:
        return rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml"))

    workflows = [(rel, text) for rel, text in files if _is_workflow(rel)]
    unreadable = _present_but_unreadable(all_paths, dict(files), _is_workflow)
    requirement = (
        "Third-party GitHub Actions must be pinned to a full commit SHA so a moved tag "
        "cannot silently change build behavior."
    )
    how = (
        "Inspect CI/CD pipeline definitions and confirm external actions are pinned to a "
        "full-length commit SHA rather than a branch or version tag."
    )
    if not workflows:
        note = (
            "No GitHub Actions workflows found under .github/workflows/."
            if not unreadable
            else "Workflow file(s) present but too large/binary to read ("
            + ", ".join(unreadable[:5])
            + "); verify their actions are SHA-pinned."
        )
        return _result(
            "protect-engineering-systems/pin-ci-actions-to-sha", 4,
            "protect-engineering-systems", requirement, "high", "manual", how, note=note,
        )

    unpinned = []
    for rel, text in workflows:
        if len(unpinned) >= _MAX_STRUCT_HITS:
            break
        for line_no, ref in _iter_action_refs(text):
            if len(unpinned) >= _MAX_STRUCT_HITS:
                break
            if ref.startswith(("./", "../", "docker://")):
                continue  # local or docker action
            if "@" not in ref:
                unpinned.append(_hit(f"uses: {ref} (no version pin)", rel, line_no, f"uses: {ref}"))
                continue
            after = ref.rsplit("@", 1)[1]  # GitHub uses the ref after the LAST @
            if not _SHA_RE.match(after):
                unpinned.append(_hit(f"uses: {ref} (tag, not SHA)", rel, line_no, f"uses: {ref}"))
    if unpinned:
        status, note = "fail", ""
    elif unreadable:
        status = "manual"
        note = (
            "All readable workflows pin actions to a SHA, but workflow file(s) could not be "
            "read (" + ", ".join(unreadable[:5]) + "); verify those are SHA-pinned too."
        )
    else:
        status, note = "pass", ""
    return _result(
        "protect-engineering-systems/pin-ci-actions-to-sha", 4,
        "protect-engineering-systems", requirement, "high", status, how,
        signal_hits=[_hit("all external actions pinned to SHA", "")] if status == "pass" else [],
        anti_signal_hits=unpinned[:25],
        note=note,
    )


_NPM_NON_REGISTRY = ("://", "git+", "file:", "link:", "workspace:", "npm:", "github:", "git:")


def _norm_include(base_dir: str, target: str) -> str:
    """Resolve a pip ``-r``/``-c`` include target to a repo-relative path, or
    return "" if it escapes the repo (absolute, drive-qualified, or ``..``)."""
    target = target.replace("\\", "/").strip().strip("\"'")
    head = target.split("/", 1)[0]
    if not target or target.startswith("/") or ":" in head:
        return ""
    joined = posixpath.normpath(posixpath.join(base_dir, target) if base_dir else target)
    if joined == ".." or joined.startswith("../") or joined.startswith("/"):
        return ""
    return joined


def _requirement_include(line: str) -> Optional[str]:
    """If ``line`` is a pip ``-r``/``-c`` include directive, return its target
    path, else ``None``. Supports ``-r f``, ``-rf``, ``--requirement f`` and
    ``--requirement=f`` (and the ``-c``/``--constraint`` equivalents)."""
    low = line.lower()
    for opt in ("--requirement", "--constraint"):
        if low.startswith(opt):
            rest = line[len(opt):]
            if rest[:1] == "=":
                arg = rest[1:]
            elif rest[:1].isspace():
                arg = rest
            else:
                return None  # e.g. a token that merely starts with --requirement
            return arg.split("#", 1)[0].strip().strip("\"'") or None
    for opt in ("-r", "-c"):
        if low.startswith(opt):
            rest = line[len(opt):]
            if rest[:1] == "=":
                arg = rest[1:]
            elif rest[:1].isspace():
                arg = rest
            elif rest and rest[0] != "-":
                arg = rest  # attached short form: -rfile.txt / -cfile.txt
            else:
                return None
            return arg.split("#", 1)[0].strip().strip("\"'") or None
    return None


def _note_unresolved(unresolved: List[str], item: str) -> None:
    """Record a pip include we could not verify, deduplicated and capped so a
    pathological file cannot grow the list without bound (or make membership
    checks quadratic)."""
    if item and len(unresolved) < _MAX_STRUCT_HITS and item not in unresolved:
        unresolved.append(item)


def _requirements_offenders(
    start_rel: str,
    text_by_rel: Dict[str, str],
    offenders: List[Dict[str, Any]],
    unresolved: List[str],
    seen: set,
) -> None:
    """Collect unpinned requirements starting at ``start_rel``, following
    ``-r``/``-c`` includes present in ``text_by_rel``. Iterative (a deep include
    chain cannot overflow the stack), cycle-guarded via ``seen``/``queued``, and
    hit-capped. Includes that cannot be resolved from the scanned files (missing,
    oversized, malformed, or outside the repo) are recorded in ``unresolved`` so
    the caller does not report an unverified clean pass."""
    stack = [start_rel]
    queued = {start_rel}
    while stack:
        if len(offenders) >= _MAX_STRUCT_HITS:
            return
        rel = stack.pop()
        if rel in seen:
            continue
        seen.add(rel)
        text = text_by_rel.get(rel)
        if text is None:
            continue
        base_dir = _dirname(rel)
        for i, raw in enumerate(text.splitlines(), start=1):
            if len(offenders) >= _MAX_STRUCT_HITS:
                return
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith(("-r", "-c", "--requirement", "--constraint")):
                target = _requirement_include(line)
                inc = _norm_include(base_dir, target) if target else ""
                if inc and inc in text_by_rel:
                    if inc not in seen and inc not in queued:
                        stack.append(inc)
                        queued.add(inc)
                elif inc:
                    _note_unresolved(unresolved, inc)  # repo-relative but not scanned
                else:
                    # missing arg, or escapes the repo (absolute/drive/.. /URL)
                    _note_unresolved(unresolved, target or line)
                continue
            if line.startswith("-"):
                continue  # other pip options (-e, --hash, --index-url, ...)
            if "://" in line or line.startswith("git+"):
                continue
            core = line.split("#", 1)[0].strip()
            spec = core.split(";", 1)[0]  # ignore PEP 508 environment markers
            if "*" in spec:
                # a wildcard such as ``==1.*`` is a range, not an exact pin
                offenders.append(_hit(f"unpinned requirement: {core}", rel, i, core))
                continue
            if "==" in spec or " @ " in spec or ("@" in spec and "://" in core):
                continue
            offenders.append(_hit(f"unpinned requirement: {core}", rel, i, core))


def _requirements_unpinned(rel: str, text: str) -> List[Dict[str, Any]]:
    """Single-file convenience wrapper (no cross-file include following)."""
    offenders: List[Dict[str, Any]] = []
    _requirements_offenders(rel, {rel: text}, offenders, [], set())
    return offenders


def _package_json_unpinned(rel: str, text: str) -> Optional[List[Dict[str, Any]]]:
    """Return unpinned dependencies, or ``None`` if the file is not a usable
    manifest (invalid JSON or a non-object top level such as ``[]``/``null``).

    A dependency is considered *pinned* only if it is an exact semver version
    (``1.2.3``). Ranges (``^``/``~``/``>=``), partial versions (``1``/``1.2``),
    ``latest``/``*``/``x`` and dist-tags are unpinned. Non-registry specifiers
    (git/url/file/link/workspace/alias) are out of scope and never flagged."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    offenders: List[Dict[str, Any]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if len(offenders) >= _MAX_STRUCT_HITS:
                break
            if not isinstance(spec, str):
                continue
            s = spec.strip()
            if not s or any(tok in s for tok in _NPM_NON_REGISTRY):
                continue  # non-registry spec -> not a floating version range
            core = s[1:].strip() if s.startswith("=") else s
            if core[:1] in ("v", "V"):
                core = core[1:]  # npm/node-semver tolerate a leading ``v`` (v1.2.3)
            if _EXACT_SEMVER.match(core):
                continue  # exact version pin
            offenders.append(_hit(f"unpinned dependency: {name}@{spec} ({section})", rel))
    return offenders


def _is_requirements_txt(rel: str) -> bool:
    """True for a pip requirements file. Covers ``requirements.txt``, a
    suffix-named ``*requirements.txt`` (``dev-requirements.txt``,
    ``test_requirements.txt``), and any ``*.txt`` inside a ``requirements/``
    directory (the common pip-tools split layout: ``requirements/base.txt``).
    Convention-based detection deliberately errs toward inspecting a file: for a
    security check, a spurious manual/fail on a stray ``requirements/*.txt`` is
    safer than silently missing unpinned dependencies in a split layout."""
    base = _basename(rel).lower()
    if not base.endswith(".txt"):
        return False
    if base.startswith("requirements") or base.endswith("requirements.txt"):
        return True
    parent = _dirname(rel).lower()
    return parent == "requirements" or parent.endswith("/requirements")


def _is_package_json(rel: str) -> bool:
    return _basename(rel).lower() == "package.json" and "/node_modules/" not in f"/{rel}"


def check_dependencies_pinned(root: Path, files: Files, all_paths: Sequence[str]) -> Dict[str, Any]:
    text_by_rel = {rel: text for rel, text in files}

    def _is_manifest(rel: str) -> bool:
        return _is_requirements_txt(rel) or _is_package_json(rel)

    manifests = 0
    offenders: List[Dict[str, Any]] = []
    unresolved: List[str] = []
    seen: set = set()
    for rel, text in files:
        if len(offenders) >= _MAX_STRUCT_HITS:
            break  # global budget: one offender already fails the check
        if _is_requirements_txt(rel):
            manifests += 1
            _requirements_offenders(rel, text_by_rel, offenders, unresolved, seen)
        elif _is_package_json(rel):
            found = _package_json_unpinned(rel, text)
            if found is None:
                _note_unresolved(unresolved, rel)  # unparseable / non-object manifest
                continue
            manifests += 1
            offenders.extend(found)
    # A manifest that exists but could not be read at all is surfaced, not ignored.
    for rel in _present_but_unreadable(all_paths, text_by_rel, _is_manifest):
        _note_unresolved(unresolved, rel)
    requirement = (
        "Dependencies should be pinned (and ideally hash-locked) so builds are reproducible "
        "and resistant to dependency-substitution attacks."
    )
    how = (
        "Check dependency manifests/lockfiles and confirm versions are pinned rather than "
        "floating ranges."
    )
    if manifests == 0 and not unresolved:
        return _result(
            "protect-engineering-systems/pin-dependency-versions", 4,
            "protect-engineering-systems", requirement, "medium", "manual", how,
            note="No requirements*.txt or package.json manifests found.",
        )
    if offenders:
        status, note, signal = "fail", "", []
    elif unresolved:
        status = "manual"
        note = (
            "Some dependency manifests or pip includes could not be read or resolved from the "
            "scanned files (missing, oversized, binary, malformed, or outside the repo): "
            + ", ".join(sorted(set(unresolved))[:5])
            + ". Verify those dependencies are pinned."
        )
        signal = []
    else:
        status, note, signal = "pass", "", [_hit("all inspected dependencies pinned", "")]
    return _result(
        "protect-engineering-systems/pin-dependency-versions", 4,
        "protect-engineering-systems", requirement, "medium", status, how,
        signal_hits=signal,
        anti_signal_hits=offenders[:_MAX_STRUCT_HITS],
        note=note,
    )


def _find_recognized(
    all_paths: Sequence[str], name: str, case_sensitive: bool = False
) -> Optional[str]:
    """Find ``name`` only where the platform actually honors it (repo root,
    ``.github/`` or ``docs/``), returning the one GitHub would use first when it
    exists in more than one location: ``.github/`` > root > ``docs/``. When
    ``case_sensitive`` (CODEOWNERS), the file name and directory must match
    exactly, because GitHub ignores a mis-cased path regardless of the OS."""
    by_dir: Dict[str, str] = {}
    for rel in all_paths:
        base = _basename(rel)
        d = _dirname(rel)
        if case_sensitive:
            if base != name or d not in _RECOGNIZED_DIRS:
                continue
        else:
            if base.lower() != name.lower() or d.lower() not in _RECOGNIZED_DIRS:
                continue
            d = d.lower()
        by_dir.setdefault(d, rel)
    for d in (".github", "", "docs"):  # GitHub precedence order
        if d in by_dir:
            return by_dir[d]
    return None


def _has_owner_rule(text: str) -> bool:
    """True if any non-comment line assigns an owner (an ``@user``/``@org/team``
    handle or an email) *after* the path pattern, so a pattern that merely
    contains ``@`` is not mistaken for ownership."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        for tok in tokens[1:]:  # tokens[0] is the path pattern; owners follow it
            if tok.startswith("#"):
                break  # rest of the line is an inline comment, not an owner
            if _OWNER_RE.match(tok) or _EMAIL_RE.match(tok):
                return True
    return False


def check_codeowners(root: Path, files: Files, all_paths: Sequence[str]) -> Dict[str, Any]:
    found = _find_recognized(all_paths, "CODEOWNERS", case_sensitive=True)
    text = dict(files).get(found) if found else None
    if not found:
        status = "fail"
        note = "Add a CODEOWNERS file (root, .github/, or docs/) and enforce it via branch protection."
    elif text is None:
        status = "manual"
        note = (
            "CODEOWNERS is present but too large or binary to read; verify by hand that it "
            "assigns owners and is enforced via branch protection."
        )
    elif _has_owner_rule(text):
        status = "pass"
        note = ""
    else:
        status = "fail"
        note = "CODEOWNERS exists but defines no owner rules (no line assigns an @owner after a pattern)."
    ok = status == "pass"
    return _result(
        "protect-engineering-systems/require-code-owner-review",
        4,
        "protect-engineering-systems",
        "A CODEOWNERS file should define required reviewers so security-relevant code cannot be "
        "merged without accountable review.",
        "high",
        status,
        "Confirm a CODEOWNERS file exists (at repo root, .github/, or docs/), assigns owners, "
        "and that branch protection requires code-owner review.",
        signal_hits=[_hit("CODEOWNERS present with owner rules", found)] if ok else [],
        anti_signal_hits=[_hit("no enforceable CODEOWNERS file", found or "")] if status == "fail" else [],
        note=note,
    )


def check_security_policy(root: Path, files: Files, all_paths: Sequence[str]) -> Dict[str, Any]:
    found = _find_recognized(all_paths, "SECURITY.md")
    status = "pass" if found else "fail"
    return _result(
        "accelerate-response-and-remediation/security-policy-present",
        6,
        "accelerate-response-and-remediation",
        "A SECURITY.md policy should document how to report vulnerabilities and how the project "
        "responds, enabling fast, coordinated remediation.",
        "medium",
        status,
        "Confirm a SECURITY.md exists (at repo root, .github/, or docs/) with a vulnerability "
        "reporting channel and response expectations.",
        signal_hits=[_hit("SECURITY.md present", found)] if found else [],
        anti_signal_hits=[] if found else [_hit("no SECURITY.md policy", "")],
        note="" if found else "Add a SECURITY.md (root, .github/, or docs/) describing vulnerability reporting and response.",
    )


_CHECKS = [
    check_tracked_env_files,
    check_actions_pinned,
    check_dependencies_pinned,
    check_codeowners,
    check_security_policy,
]


def run_structural_checks(
    root: Path, files: Files, all_paths: Sequence[str]
) -> List[Dict[str, Any]]:
    return [check(root, files, all_paths) for check in _CHECKS]
