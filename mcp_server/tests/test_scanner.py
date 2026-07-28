"""Tests for the SFI scanner: matching, redaction, excludes, and fixture regression."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from conftest import FIXTURES, REPO_ROOT
from sfi_audit import matching, report
from sfi_audit.checks import structural
from sfi_audit.scanner import audit_repository, iter_repo_files


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "token,is_regex",
    [
        ("AKIA[0-9A-Z]{16}", True),
        ("-----BEGIN (RSA )?PRIVATE KEY-----", True),
        (r"(?i)\bMD5\b", True),
        ("process.env.", False),          # lone dots stay literal
        ("AZURE_CLIENT_SECRET", False),
        ("publicNetworkAccess: Enabled", False),
    ],
)
def test_regex_classification(token, is_regex):
    assert matching.looks_like_regex(token) is is_regex


def test_literal_match_is_case_insensitive():
    m = matching.build_matcher("AZURE_CLIENT_SECRET")
    line = "  azure_client_secret = 'x'"
    assert matching.search_line(m, line, line.lower()) is not None


def test_regex_word_boundary_avoids_substring_false_positive():
    m = matching.build_matcher(r"\bDES\b")
    # Must NOT match inside 'destination'; case-sensitive whole word only.
    line = "destination_port_range = 22"
    assert matching.search_line(m, line, line.lower()) is None
    hit = "cipher = DES"
    assert matching.search_line(m, hit, hit.lower()) is not None


def test_redaction_masks_secret_values():
    redacted = matching.redact('client_secret = "s3cr3t-value-abcdefgh"')
    assert "s3cr3t-value-abcdefgh" not in redacted
    assert "redacted" in redacted


# --------------------------------------------------------------------------- #
# file walking / excludes
# --------------------------------------------------------------------------- #
def test_iter_repo_files_honors_excludes(tmp_path):
    (tmp_path / "keep.txt").write_text("hello", encoding="utf-8")
    skip = tmp_path / "external"          # not a default-ignored dir name
    skip.mkdir()
    (skip / "lib.txt").write_text("world", encoding="utf-8")

    all_files = {rel for rel, _ in iter_repo_files(tmp_path)}
    assert "keep.txt" in all_files and "external/lib.txt" in all_files

    pruned = {rel for rel, _ in iter_repo_files(tmp_path, ["external"])}
    assert "keep.txt" in pruned and "external/lib.txt" not in pruned


def test_iter_repo_files_skips_ignored_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print(1)", encoding="utf-8")
    files = {rel for rel, _ in iter_repo_files(tmp_path)}
    assert "src/a.py" in files
    assert not any(rel.startswith(".git/") for rel in files)


# -- round-11 (opus-4.6): iter_repo_files must honour its (str, str) contract  #
# -- and never yield a None body for oversized/unreadable in-scope text ------ #
def test_iter_repo_files_never_yields_none_body_for_oversized_text(tmp_path):
    (tmp_path / "small.txt").write_text("hello", encoding="utf-8")
    big = tmp_path / "big.txt"
    big.write_text("A" * 1_000_001, encoding="utf-8")  # > MAX_FILE_BYTES

    stats = {"truncated": False}
    yielded = list(iter_repo_files(tmp_path, stats=stats))

    names = {rel for rel, _ in yielded}
    assert "small.txt" in names
    assert "big.txt" not in names                     # oversized text not yielded
    assert all(text is not None for _, text in yielded)  # contract: never None
    assert stats["truncated"] is True                 # incompleteness surfaced


def test_audit_clean_repo_has_no_failures(tmp_path):
    # A structurally complete, benign repo should produce zero automated failures.
    (tmp_path / "README.md").write_text("# clean project\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @team\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(
        "# Security\nReport issues to security@example.test\n", encoding="utf-8"
    )
    audit = audit_repository(tmp_path)
    failed = [r["id"] for r in audit["results"] if r["status"] == "fail"]
    assert failed == [], f"unexpected failures on clean repo: {failed}"


# --------------------------------------------------------------------------- #
# fixture regression (golden expectations)
# --------------------------------------------------------------------------- #
def _status_map(audit):
    return {r["id"]: r["status"] for r in audit["results"]}


@pytest.mark.parametrize("fixture", ["compliant", "noncompliant"])
def test_fixture_regression(fixture):
    fixture_dir = FIXTURES / fixture
    expected = json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))

    audit = audit_repository(fixture_dir)
    statuses = _status_map(audit)
    scorecard = report.build_scorecard(audit)
    overall = scorecard["overall"]

    for cid in expected["must_fail"]:
        assert statuses.get(cid) == "fail", f"{fixture}: expected FAIL for {cid}, got {statuses.get(cid)}"
    for cid in expected["must_pass"]:
        assert statuses.get(cid) == "pass", f"{fixture}: expected PASS for {cid}, got {statuses.get(cid)}"

    exp_overall = expected["overall"]
    if "allowed_grades" in exp_overall:
        assert overall["grade"] in exp_overall["allowed_grades"]
    if "min_score" in exp_overall and overall["score"] is not None:
        assert overall["score"] >= exp_overall["min_score"]
    if "max_failed" in exp_overall:
        assert overall["failed"] <= exp_overall["max_failed"]
    if "min_failed" in exp_overall:
        assert overall["failed"] >= exp_overall["min_failed"]


def test_scanner_never_writes_to_target(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    before = {p.name for p in tmp_path.iterdir()}
    audit_repository(tmp_path)
    after = {p.name for p in tmp_path.iterdir()}
    assert before == after


def test_evidence_is_redacted_in_findings():
    audit = audit_repository(FIXTURES / "noncompliant")
    for r in audit["results"]:
        for hit in r.get("anti_signal_hits", []):
            snippet = hit.get("snippet", "")
            # The planted fake secrets must never appear verbatim in evidence.
            assert "wJalrXUtnFEMI" not in snippet
            assert "ghp_EXAMPLE0123456789abcdefABCDEF01234567" not in snippet


# --------------------------------------------------------------------------- #
# regression: opus-4.6 code review findings (2026-07)
# --------------------------------------------------------------------------- #
def _kb_anti_signals():
    data = json.loads((REPO_ROOT / "data" / "sfi_checklists.json").read_text(encoding="utf-8"))
    tokens = []
    for c in data["checklist"]:
        tokens.extend(c.get("anti_signals", []))
    return tokens


def _matches(token, line):
    m = matching.build_matcher(token)
    return matching.search_line(m, line, line.lower()) is not None


@pytest.mark.parametrize(
    "line",
    [
        "  actions: ['*']",                       # Bicep, single quotes
        '      "actions": ["*"]',                 # ARM JSON, double quotes
        "  dataActions: ['*']",
        "  allowedTenants: ['*']",
        "  AdditionallyAllowedTenants: ['*']",
        '  "destinationAddresses": ["*"]',
    ],
)
def test_wildcard_iac_anti_signals_match(line):
    # Regression: the ['*'] tokens were classified as regex character classes and
    # silently never matched. A wildcard IAM/tenant/egress line must be flagged.
    assert any(_matches(t, line) for t in _kb_anti_signals()), line


def test_wildcard_tokens_compile_as_regex():
    wild = [t for t in _kb_anti_signals() if "\\[" in t and "\\*" in t]
    assert len(wild) >= 5
    for tok in wild:
        assert matching.build_matcher(tok).mode == "regex"


@pytest.mark.parametrize("word", ["footprint()", "sprint()", "get_fingerprint()"])
def test_print_anti_signal_ignores_substrings(word):
    tokens = [t for t in _kb_anti_signals() if "print" in t.lower()]
    assert tokens
    assert not any(_matches(t, f"    {word}") for t in tokens), word


def test_print_anti_signal_flags_real_print():
    tokens = [t for t in _kb_anti_signals() if "print" in t.lower()]
    assert any(_matches(t, '    print("debug", x)') for t in tokens)


@pytest.mark.parametrize(
    "line,flagged",
    [
        ('requests ; python_version == "3.8"', True),
        ('requests>=2.0 ; python_version == "3.8"', True),
        ("requests", True),
        ("requests==2.0", False),
        ('requests==2.0 ; python_version == "3.8"', False),
        ("pkg @ ./local", False),
    ],
)
def test_requirements_marker_does_not_hide_unpinned(line, flagged):
    offenders = structural._requirements_unpinned("requirements.txt", line)
    assert bool(offenders) is flagged, line


@pytest.mark.parametrize(
    "secret,line",
    [
        ("MyP@ss!1", "DB_PASS=MyP@ss!1"),
        ("abc123xyz", "token=abc123xyz"),
        ("shortkey99", "key=shortkey99"),
        ("pass123", 'SECRET="pass123"'),
    ],
)
def test_short_secrets_are_redacted(secret, line):
    assert secret not in matching.redact(line)


# --------------------------------------------------------------------------- #
# regression: rubber-duck (gpt-5.6-sol) confirmation findings (2026-07)
# --------------------------------------------------------------------------- #
def _checklist():
    return json.loads(
        (REPO_ROOT / "data" / "sfi_checklists.json").read_text(encoding="utf-8")
    )["checklist"]


def _kb_signals():
    tokens = []
    for c in _checklist():
        tokens.extend(c.get("signals", []))
    return tokens


# -- B2: standalone secret redaction -------------------------------------- #
@pytest.mark.parametrize(
    "secret,line",
    [
        ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),                 # bare AWS key id, no assignment
        ("ghp_0123456789abcdefghij0123456789abcdef",
         "  ghp_0123456789abcdefghij0123456789abcdef  "),               # bare GitHub token
        ("AIzaSyA0123456789abcdefghijklmnopqrstuv",
         "url = maps?key=AIzaSyA0123456789abcdefghijklmnopqrstuv"),      # Google key
        ("eyJhbGciOiJIUzI1.eyJzdWIiOjEyMzQ1.SflKxwRJSMeKKF2QT4",
         "authorization eyJhbGciOiJIUzI1.eyJzdWIiOjEyMzQ1.SflKxwRJSMeKKF2QT4"),  # JWT, space-separated
    ],
)
def test_standalone_secret_tokens_are_redacted(secret, line):
    assert secret not in matching.redact(line)


def test_bearer_token_is_redacted_but_keyword_kept():
    out = matching.redact("send Authorization Bearer abcdef0123456789xyztoken now")
    assert "abcdef0123456789xyztoken" not in out
    assert "Bearer" in out


def test_private_key_header_is_redacted():
    assert "PRIVATE KEY" not in matching.redact("-----BEGIN OPENSSH PRIVATE KEY-----")


# --------------------------------------------------------------------------- #
# regression: round-11 redaction hardening (gpt-5.6-sol findings s1-s7)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line,leak",
    [
        # s1: key-aware masking of shapes the generic matchers miss
        ("<servicePrincipalPassword>Zm9vYmFyLXNlY3JldA==</servicePrincipalPassword>",
         "Zm9vYmFyLXNlY3JldA=="),                                   # XML element
        ("setx AZURE_CLIENT_SECRET Zm9vYmFyLXNlY3JldA", "Zm9vYmFyLXNlY3JldA"),   # setx NAME value
        ("setx /M AZURE_CLIENT_SECRET Zm9vYmFyLXNlY3JldA", "Zm9vYmFyLXNlY3JldA"),  # setx with flag
        # round-11 (rubber-duck): quoted multi-word setx value must not leak its tail
        ('setx AZURE_CLIENT_SECRET "alpha bravo charlie"', "bravo charlie"),
        ("clientSecret: my multi word secret phrase", "multi word secret phrase"),   # multi-word value
        ("connectionString: Server=a;Password=Zm9vYmFyLXNlY3JldA;Db=b",
         "Zm9vYmFyLXNlY3JldA"),                                     # connection string
        # s2: sub-6-char value still masked because the key is secret-bearing
        ("pwd=abc", "abc"),
        ("api_key: xy", "xy"),
        # s4: bearer token containing base64 (/ + =) chars is fully masked
        ("Authorization: Bearer abcd/efgh+ijkl==mnop", "abcd/efgh+ijkl==mnop"),
    ],
)
def test_key_aware_and_bearer_redaction(line, leak):
    assert leak not in matching.redact(line)


def test_flattened_pem_body_is_redacted():
    # A PEM key flattened onto one physical line (literal ``\n`` separators, no
    # real newline) must not leak its base64 body after the header is masked.
    body = "MIIBODY0123456789abcdefGHIJKLMNOP"
    line = f"-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----"
    assert body not in matching.redact(line)


def test_redaction_is_linear_on_crafted_backslash_run():
    # s5: disjoint quoted-value branches must not catastrophically backtrack on
    # an unbalanced run of backslashes inside a quote.
    line = '"' + ("\\" * 5000) + "x"
    start = time.perf_counter()
    matching.redact(line)
    assert time.perf_counter() - start < 2.0


def test_regex_search_is_bounded_on_very_long_line():
    # s6: a regex signal search on a pathological long line must stay fast while
    # still finding a marker near the start of the line.
    m = matching.build_matcher(r"secret\d+")
    line = "secret123" + ("a" * 200000)
    start = time.perf_counter()
    span = matching.search_line(m, line, line.lower())
    assert time.perf_counter() - start < 2.0
    assert span == (0, len("secret123"))


# -- B5: unknown pillar must raise, not silently audit nothing ------------- #
def test_unknown_pillar_filter_raises():
    with pytest.raises(ValueError):
        audit_repository(REPO_ROOT, pillars=["not-a-pillar"], exclude=["data", "staging"])


def test_known_pillar_filter_is_accepted():
    audit = audit_repository(REPO_ROOT, pillars=[1], exclude=["data", "staging", "reports"])
    assert audit["results"], "a valid pillar filter should still return criteria"


# -- B6: malformed package.json is not a usable manifest ------------------- #
@pytest.mark.parametrize("text", ["[]", "null", "\"str\"", "123", "{ not json"])
def test_malformed_package_json_returns_none(text):
    assert structural._package_json_unpinned("package.json", text) is None


def test_valid_package_json_pinning_detection():
    assert structural._package_json_unpinned(
        "package.json", '{"dependencies": {"x": "1.0.0"}}'
    ) == []
    flagged = structural._package_json_unpinned(
        "package.json", '{"dependencies": {"x": "^1.0.0"}}'
    )
    assert len(flagged) == 1


def test_malformed_manifest_does_not_false_pass(tmp_path):
    (tmp_path / "package.json").write_text("[]", encoding="utf-8")
    audit = audit_repository(tmp_path)
    statuses = {r["id"]: r["status"] for r in audit["results"]}
    dep = next(k for k in statuses if k.endswith("pin-dependency-versions"))
    assert statuses[dep] == "manual"  # no usable manifest -> undetermined, never pass


# -- B7: symlinks are never followed -------------------------------------- #
def test_symlinks_are_skipped(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("hello\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")
    scanned = {rel for rel, _ in iter_repo_files(tmp_path)}
    assert "real.txt" in scanned
    assert "link.txt" not in scanned


# -- B1: never write a scorecard into the audited tree unless opted in ----- #
def test_scorecard_refuses_write_inside_audited_repo(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        report.generate_scorecard(tmp_path, out_dir=tmp_path / "reports")
    res = report.generate_scorecard(
        tmp_path, out_dir=tmp_path / "reports", allow_in_tree=True
    )
    assert Path(res["json_path"]).exists()


def test_scorecard_writes_outside_audited_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    res = report.generate_scorecard(repo, out_dir=out)
    assert Path(res["json_path"]).exists()


# -- B3/B4: KB token hygiene ---------------------------------------------- #
def test_policytypes_signal_is_precise():
    tok = next(t for t in _kb_signals() if "policytypes" in t.lower())
    assert _matches(tok, "  policyTypes: [Ingress, Egress]")
    assert _matches(tok, "        policyTypes: [Egress]")
    assert not _matches(tok, "  policyTypes: Ingress")  # old broken char-class behavior


def test_generic_lone_word_signals_removed():
    for c in _checklist():
        for s in c.get("signals", []):
            assert s.strip().lower() not in {"scope", "owner", "owners"}, (c["id"], s)


def test_no_unmatchable_glob_signals_remain():
    for c in _checklist():
        for s in c.get("signals", []) + c.get("anti_signals", []):
            assert "**/" not in s, (c["id"], s)


def test_iac_content_markers_match():
    sigs = _kb_signals()
    assert any(_matches(t, 'resource "azurerm_key_vault" "kv" {') for t in sigs)
    assert any(_matches(t, "  Microsoft.Network/virtualNetworks") for t in sigs)


# --------------------------------------------------------------------------- #
# regression: round-2 multi-model audit (gpt-5.6-terra / gemini-3.1-pro /
# mai-code-1-flash), triaged & fixed 2026-07
# --------------------------------------------------------------------------- #
# -- T1: NTFS junctions / reparse points are never followed ---------------- #
def test_ntfs_junction_is_not_followed(tmp_path):
    import subprocess

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("PASSWORD=hunter2hunter2\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    junction = repo / "linked"
    try:
        rc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True, text=True,
        )
    except (FileNotFoundError, OSError):
        pytest.skip("mklink/junctions not available on this platform")
    if rc.returncode != 0 or not junction.exists():
        pytest.skip("could not create an NTFS junction in this environment")
    scanned = {rel for rel, _ in iter_repo_files(repo)}
    assert "app.py" in scanned
    assert not any(rel.startswith("linked/") for rel in scanned), scanned


# -- T2: an oversized tracked .env is still flagged by presence ------------- #
def test_oversized_env_file_is_still_flagged(tmp_path):
    # > MAX_FILE_BYTES so content scanning skips it; presence must still catch it.
    (tmp_path / ".env").write_text("#" + "x" * 1_100_000, encoding="utf-8")
    audit = audit_repository(tmp_path)
    statuses = {r["id"]: r["status"] for r in audit["results"]}
    assert statuses["protect-identities-and-secrets/no-tracked-env-files"] == "fail"


# -- T4a: npm partial/loose versions are unpinned; exact semver is pinned --- #
@pytest.mark.parametrize(
    "spec,flagged",
    [
        ("1.2.3", False), ("=1.2.3", False), ("1.2.3-rc.1", False), ("1.2.3+build.5", False),
        ("v1.2.3", False), ("V1.2.3", False), ("=v1.2.3", False), ("v1.2.3-rc.1", False),
        ("1", True), ("1.2", True), ("^1.2.3", True), ("~1.0.0", True),
        (">=1.0.0", True), ("latest", True), ("1.x", True), ("*", True),
        ("v1", True), ("vlatest", True),
    ],
)
def test_npm_exact_semver_pinning(spec, flagged):
    text = json.dumps({"dependencies": {"pkg": spec}})
    offenders = structural._package_json_unpinned("package.json", text)
    assert bool(offenders) is flagged, spec


@pytest.mark.parametrize(
    "spec",
    ["git+https://x/y.git", "file:../local", "workspace:*", "npm:left-pad@1.0.0",
     "https://x/y.tgz", "github:owner/repo"],
)
def test_npm_non_registry_specs_are_out_of_scope(spec):
    text = json.dumps({"dependencies": {"pkg": spec}})
    assert structural._package_json_unpinned("package.json", text) == []


# -- T4b: pip -r/-c includes are followed so they cannot hide unpinned deps - #
def test_requirements_include_is_followed(tmp_path):
    (tmp_path / "base.txt").write_text("flask\n", encoding="utf-8")  # unpinned
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\nrequests==2.31.0\n", encoding="utf-8"
    )
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "fail"
    assert "base.txt" in {h["file"] for h in dep["anti_signal_hits"]}


def test_requirements_include_cycle_is_safe(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r a.txt\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("-r requirements.txt\ndjango\n", encoding="utf-8")
    audit = audit_repository(tmp_path)  # must terminate, not recurse forever
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "fail"


# -- round-11 (opus-4.8 B1): split requirements layouts are detected ------- #
@pytest.mark.parametrize(
    "path",
    ["requirements/base.txt", "requirements/prod.txt",
     "dev-requirements.txt", "test_requirements.txt"],
)
def test_split_requirements_layout_is_audited(tmp_path, path):
    p = tmp_path / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("flask\n", encoding="utf-8")  # unpinned -> must be caught
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "fail", path


def test_split_requirements_pinned_layout_passes(tmp_path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "pass"


# -- round-11 (opus-4.8 M1/B2): env allow-list is an exact-segment match --- #
@pytest.mark.parametrize(
    "name,flagged",
    [
        (".env", True),
        (".env.production", True),
        (".env.distprod", True),      # 'dist' substring must NOT excuse it
        (".env.example", False),
        (".env.template", False),
        (".env.tmpl", False),         # template shorthand now allowed
        (".env.tpl", False),
        (".env.local.example", False),
    ],
)
def test_env_allowlist_is_exact_segment(tmp_path, name, flagged):
    (tmp_path / name).write_text("SECRET=x\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    env = next(r for r in audit["results"] if r["id"].endswith("no-tracked-env-files"))
    assert (env["status"] == "fail") is flagged, name


# -- T5: a quoted `uses:` key does not hide an unpinned action ------------- #
def test_quoted_uses_key_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        'jobs:\n  b:\n    steps:\n      - "uses": actions/checkout@v4\n', encoding="utf-8"
    )
    audit = audit_repository(tmp_path)
    act = next(r for r in audit["results"] if r["id"].endswith("pin-ci-actions-to-sha"))
    assert act["status"] == "fail"


# -- T6: a bare AWS secret paired with an access-key id is redacted -------- #
def test_aws_secret_key_pair_is_redacted():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40-char AWS secret
    line = f"AKIAIOSFODNN7EXAMPLE,{secret}"  # comma-separated: no '='/quote delimiter
    out = matching.redact(line)
    assert secret not in out


def test_bare_40char_token_without_aws_context_is_left_alone():
    # A 40-char hex git SHA on an unrelated line must NOT be redacted.
    sha = "a" * 40
    assert sha in matching.redact(f"pinned to {sha} in lockfile")


# -- T7: excludes are case-insensitive and ignore a leading ./ ------------- #
@pytest.mark.parametrize("exclude", ["secrets", "./Secrets", "SECRETS/"])
def test_excludes_are_normalized(tmp_path, exclude):
    d = tmp_path / "Secrets"
    d.mkdir()
    (d / "a.txt").write_text("hi\n", encoding="utf-8")
    (tmp_path / "keep.txt").write_text("hi\n", encoding="utf-8")
    scanned = {rel for rel, _ in iter_repo_files(tmp_path, [exclude])}
    assert "keep.txt" in scanned
    assert not any(r.lower().startswith("secrets/") for r in scanned), (exclude, scanned)


# -- T8: CODEOWNERS/SECURITY.md only count in honored locations ------------ #
def test_codeowners_in_unrecognized_dir_does_not_pass(tmp_path):
    sub = tmp_path / "random"
    sub.mkdir()
    (sub / "CODEOWNERS").write_text("* @team\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "fail"


def test_codeowners_without_owner_rule_fails(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("# owners TBD\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "fail"


@pytest.mark.parametrize("subdir", ["", ".github", "docs"])
def test_codeowners_in_recognized_dir_with_owner_passes(tmp_path, subdir):
    base = tmp_path / subdir if subdir else tmp_path
    base.mkdir(parents=True, exist_ok=True)
    (base / "CODEOWNERS").write_text("* @team\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "pass", subdir


def test_security_policy_in_unrecognized_dir_does_not_pass(tmp_path):
    sub = tmp_path / "random"
    sub.mkdir()
    (sub / "SECURITY.md").write_text("# report to security@\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    sec = next(r for r in audit["results"] if r["id"].endswith("security-policy-present"))
    assert sec["status"] == "fail"


# -- T9: a non-ASCII "digit" pillar key must not crash get_pillar --------- #
@pytest.mark.parametrize("key", ["\u00b2", "\u2081", "\u0967", "\u2460"])
def test_get_pillar_handles_unicode_digits(key):
    from sfi_audit import knowledge

    assert knowledge.get_pillar(key) is None  # must return None, never raise


# -- T10: generate_scorecard surfaces an OSError as a clean error --------- #
def test_generate_scorecard_out_dir_is_a_file(tmp_path):
    from sfi_audit import server

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    out_file = tmp_path / "out"
    out_file.write_text("i am a file, not a dir\n", encoding="utf-8")
    res = server.generate_scorecard(str(repo), out_dir=str(out_file))
    assert "error" in res  # OSError caught, not raised


# -- M3: the harness CLI exits 2 (not a traceback) on an in-tree write ----- #
def test_run_audit_cli_exits_2_on_in_tree_write(tmp_path):
    import sys as _sys

    if str(REPO_ROOT) not in _sys.path:
        _sys.path.insert(0, str(REPO_ROOT))
    from harness import run_audit

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = run_audit.main([str(repo), "--out", str(repo / "reports")])
    assert rc == 2


# -- round-11 (mai m2): the harness CLI self-audit exits clean ------------- #
def test_run_audit_cli_self_audit_is_clean(capsys):
    import sys as _sys

    if str(REPO_ROOT) not in _sys.path:
        _sys.path.insert(0, str(REPO_ROOT))
    from harness import run_audit

    rc = run_audit.main(["--self", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0, "self-audit must have no hard failures"
    card = json.loads(out)
    assert card["overall"]["score"] == 100
    assert card["overall"]["grade"] == "A"
    assert card["overall"]["failed"] == 0


# -- truncation is surfaced in the scan metadata -------------------------- #
def test_scan_reports_truncated_flag(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    assert audit["scanned"]["truncated"] is False


# -- s7: oversized/unreadable text is surfaced as an incomplete scan ------- #
def test_oversized_text_file_marks_scan_incomplete(tmp_path):
    # An oversized *text* file is skipped for content scanning, but that must
    # surface as an incomplete scan (truncated + counted) so an absence-based
    # ``pass`` is never silently based on text that was never read.
    (tmp_path / "big.py").write_text("x = 1\n" + "# pad " * 200_000, encoding="utf-8")
    (tmp_path / "small.py").write_text("y = 2\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    assert audit["scanned"]["truncated"] is True
    assert audit["scanned"]["files_skipped"] >= 1


def test_binary_file_does_not_mark_scan_incomplete(tmp_path):
    # A genuinely binary file is out of scope: it must NOT be counted as skipped
    # or flip the incomplete flag (its absence from content scanning is expected).
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    audit = audit_repository(tmp_path)
    assert audit["scanned"]["truncated"] is False
    assert audit["scanned"]["files_skipped"] == 0


# --------------------------------------------------------------------------- #
# regression: /rubber-duck confirmation pass (gpt-5.6-sol), 2026-07
# --------------------------------------------------------------------------- #
# -- rd1: a truncated scan is surfaced in the scorecard and markdown -------- #
def test_truncated_scan_is_surfaced_in_scorecard_and_markdown():
    audit = {
        "repository": "X", "generated_at": "now", "kb_version": "1",
        "scanned": {"files": 1, "files_seen": 1, "truncated": True},
        "results": [],
    }
    card = report.build_scorecard(audit)
    assert card["overall"]["incomplete"] is True
    assert "Incomplete scan" in report.render_markdown(card)

    audit["scanned"]["truncated"] = False
    card2 = report.build_scorecard(audit)
    assert card2["overall"]["incomplete"] is False
    assert "Incomplete scan" not in report.render_markdown(card2)


# -- round-11 (opus-4.8 C1): scoring never rounds to a misleading extreme -- #
def test_score_never_rounds_to_misleading_extreme():
    # 199 passes + 1 fail (weight 1) = 99.5% must floor to 99, not round to 100.
    near_perfect = [{"status": "pass", "severity": "low"} for _ in range(199)]
    near_perfect.append({"status": "fail", "severity": "low"})
    assert report._score(near_perfect) == 99
    # 1 pass among 300 fails = 0.33% must ceil to 1, not round to 0.
    near_zero = [{"status": "fail", "severity": "low"} for _ in range(300)]
    near_zero.append({"status": "pass", "severity": "low"})
    assert report._score(near_zero) == 1
    # a genuinely clean result is still exactly 100, and all-manual is None.
    assert report._score([{"status": "pass", "severity": "high"}]) == 100
    assert report._score([{"status": "manual", "severity": "high"}]) is None


# -- rd2a: pip attached short include (-rfile.txt, no space) is followed ---- #
def test_requirements_attached_short_include_is_followed(tmp_path):
    (tmp_path / "base.txt").write_text("flask\n", encoding="utf-8")  # unpinned
    (tmp_path / "requirements.txt").write_text("-rbase.txt\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "fail"
    assert "base.txt" in {h["file"] for h in dep["anti_signal_hits"]}


# -- rd2b: wildcard equality (==1.*) is a range, not an exact pin ----------- #
@pytest.mark.parametrize(
    "line,flagged",
    [("pkg==1.*", True), ("pkg==1.0.*", True), ("pkg==1.2.3", False)],
)
def test_requirements_wildcard_equality_is_unpinned(line, flagged):
    offenders = structural._requirements_unpinned("requirements.txt", line)
    assert bool(offenders) is flagged, line


# -- rd2c: an include that cannot be resolved must not report a clean pass -- #
def test_requirements_unresolved_include_is_manual(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r missing-prod.txt\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "manual"
    assert "missing-prod.txt" in dep["note"]


# -- rd2d: a deep -r chain is handled iteratively (no RecursionError) ------- #
def test_requirements_deep_include_chain_does_not_recurse():
    n = 2000  # far beyond Python's default recursion limit
    text_by_rel = {f"r{i}.txt": f"-r r{i + 1}.txt\n" for i in range(n)}
    text_by_rel[f"r{n}.txt"] = "flask\n"  # unpinned dep at the end of the chain
    offenders: list = []
    unresolved: list = []
    structural._requirements_offenders("r0.txt", text_by_rel, offenders, unresolved, set())
    assert any(h["file"] == f"r{n}.txt" for h in offenders)


# -- rd4: a flow-style `{ uses: ... }` action is still detected ------------- #
def test_flow_style_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - { uses: actions/checkout@v4 }\n", encoding="utf-8"
    )
    audit = audit_repository(tmp_path)
    act = next(r for r in audit["results"] if r["id"].endswith("pin-ci-actions-to-sha"))
    assert act["status"] == "fail"


# -- rd5a: full semver with prerelease AND build metadata is an exact pin --- #
@pytest.mark.parametrize("spec", ["1.2.3-rc.1+build.5", "1.2.3+build.5", "1.2.3-alpha"])
def test_npm_full_semver_metadata_is_pinned(spec):
    text = json.dumps({"dependencies": {"pkg": spec}})
    assert structural._package_json_unpinned("package.json", text) == [], spec


# -- rd5b: full-width/Unicode digits do not satisfy the ASCII semver pin ---- #
def test_npm_fullwidth_digits_are_not_pinned():
    text = json.dumps({"dependencies": {"pkg": "\uff11.\uff12.\uff13"}})
    assert structural._package_json_unpinned("package.json", text)  # flagged


# -- rd6a: a pathologically long numeric pillar key must not crash ---------- #
def test_get_pillar_handles_huge_numeric_key():
    from sfi_audit import knowledge

    assert knowledge.get_pillar("9" * 5000) is None  # no integer-conversion crash


# -- rd6b: the generated KB uses LF newlines (byte-identical across OSes) --- #
def test_kb_files_use_lf_newlines():
    from sfi_audit import knowledge

    data_dir = knowledge.find_data_dir()
    for name in ("sfi_pillars.json", "sfi_checklists.json", "sources.json"):
        assert b"\r\n" not in (data_dir / name).read_bytes(), name


# -- rd3a: '@' only inside the path pattern is not an owner assignment ------ #
def test_codeowners_owner_only_in_pattern_does_not_count(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("@weird-path-token\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "fail"


# -- rd3b: GitHub precedence — .github/ wins over an empty docs/ CODEOWNERS -- #
def test_codeowners_github_dir_takes_precedence(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("* @team\n", encoding="utf-8")
    (tmp_path / "docs" / "CODEOWNERS").write_text("# no owners here\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "pass"


# -- rd3c: a CODEOWNERS too large to read is manual, not an automatic pass -- #
def test_codeowners_too_large_to_read_is_manual(tmp_path):
    (tmp_path / "CODEOWNERS").write_text(
        "* @team\n#" + "x" * 1_100_000, encoding="utf-8"  # > MAX_FILE_BYTES
    )
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "manual"


# -- rd8a: an include that leaves the repo (.., absolute, URL) is manual ----- #
@pytest.mark.parametrize("target", ["../shared.txt", "/etc/base.txt", "https://x/req.txt"])
def test_requirements_external_include_is_manual(tmp_path, target):
    (tmp_path / "requirements.txt").write_text(f"-r {target}\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "manual"
    assert target in dep["note"]


# -- rd8a2: a bare `-r` with no argument cannot be verified => manual -------- #
def test_requirements_bare_include_directive_is_manual(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    dep = next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))
    assert dep["status"] == "manual"


# -- rd8b: a `uses` that is not first in a flow mapping is still detected ---- #
def test_reordered_flow_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        "      - { name: Checkout, uses: actions/checkout@v4 }\n",
        encoding="utf-8",
    )
    audit = audit_repository(tmp_path)
    act = next(r for r in audit["results"] if r["id"].endswith("pin-ci-actions-to-sha"))
    assert act["status"] == "fail"


# -- rd8b2: a SHA-pinned reordered flow mapping is not a false positive ------ #
def test_reordered_flow_uses_sha_pinned_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - {{ name: Checkout, uses: actions/checkout@{sha} }}\n",
        encoding="utf-8",
    )
    audit = audit_repository(tmp_path)
    act = next(r for r in audit["results"] if r["id"].endswith("pin-ci-actions-to-sha"))
    assert act["status"] == "pass"


# -- rd8c: a bare `@` (no handle) is not a valid CODEOWNERS owner ------------ #
def test_codeowners_bare_at_does_not_count(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* @\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    co = next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))
    assert co["status"] == "fail"


# ========================================================================== #
# Round-4 rubber-duck confirmation follow-ups (rd9)                           #
# ========================================================================== #

def _dep(audit):
    return next(r for r in audit["results"] if r["id"].endswith("pin-dependency-versions"))


def _act(audit):
    return next(r for r in audit["results"] if r["id"].endswith("pin-ci-actions-to-sha"))


def _co(audit):
    return next(r for r in audit["results"] if r["id"].endswith("require-code-owner-review"))


# -- rd9a: a UTF-8 BOM on the first line does not hide an include ----------- #
def test_bom_prefixed_requirements_include_is_not_hidden(tmp_path):
    (tmp_path / "requirements.txt").write_text("\ufeff-r ../shared.txt\n", encoding="utf-8")
    dep = _dep(audit_repository(tmp_path))
    assert dep["status"] == "manual"  # BOM stripped; external include -> unresolved


def test_bom_prefixed_requirements_unpinned_is_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text("\ufeffrequests\n", encoding="utf-8")
    dep = _dep(audit_repository(tmp_path))
    assert dep["status"] == "fail"  # BOM stripped; bare requirement still unpinned


# -- rd9b: a manifest present but too large to read is manual, not pass ----- #
def test_unreadable_manifest_alongside_clean_one_is_manual(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")  # pinned
    (tmp_path / "package.json").write_text("{}\n" + "x" * 1_100_000, encoding="utf-8")  # > MAX
    dep = _dep(audit_repository(tmp_path))
    assert dep["status"] == "manual"
    assert "package.json" in dep["note"]


# -- rd9c: a malformed package.json next to a clean manifest is manual ------ #
def test_malformed_manifest_alongside_clean_one_is_manual(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")  # pinned
    (tmp_path / "package.json").write_text("[]", encoding="utf-8")  # not an object
    dep = _dep(audit_repository(tmp_path))
    assert dep["status"] == "manual"


# -- rd9d: a workflow present but too large to read is manual, not pass ----- #
def test_unreadable_workflow_alongside_pinned_one_is_manual(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@{sha}\n", encoding="utf-8"
    )
    (wf / "big.yml").write_text("jobs:\n#" + "x" * 1_100_000, encoding="utf-8")  # > MAX
    act = _act(audit_repository(tmp_path))
    assert act["status"] == "manual"
    assert "big.yml" in act["note"]


# -- rd9e: a uses in a first-key flow mapping is detected ------------------- #
def test_first_key_flow_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  call: { uses: acme/repo/.github/workflows/reuse.yml@main }\n", encoding="utf-8"
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd9f: a uses in a flow *sequence* is detected -------------------------- #
def test_flow_sequence_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps: [{ uses: actions/checkout@v4 }]\n", encoding="utf-8"
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd9g: JSON embedded in a `run:` scalar is not a false action match ----- #
def test_run_string_json_is_not_a_false_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - run: echo '{\"name\":\"x\", \"uses\":\"actions/evil@v1\"}'\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd9h: a `uses:` line inside a `run: |` block scalar is not scored ------ #
def test_block_scalar_uses_text_is_not_a_false_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        "      - name: x\n        run: |\n          uses: not-an-action\n"
        f"      - uses: actions/real@{sha}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd9i: an owner hidden behind an inline comment does not count ---------- #
def test_codeowners_inline_comment_owner_does_not_count(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* # @team\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "fail"


# -- rd9j: an Enterprise Managed User handle (underscore) is a valid owner -- #
def test_codeowners_emu_underscore_owner_passes(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* @mona-cat_contoso\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "pass"


# ========================================================================== #
# Round-5 rubber-duck confirmation follow-ups (rd10)                          #
# ========================================================================== #

# -- rd10a: GitHub honors CODEOWNERS only at the exact name/case ------------- #
def test_miscased_codeowners_is_not_honored(tmp_path):
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "codeowners").write_text("* @contoso/team\n", encoding="utf-8")  # wrong case
    assert _co(audit_repository(tmp_path))["status"] == "fail"


def test_exact_case_codeowners_is_honored(tmp_path):
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "CODEOWNERS").write_text("* @contoso/team\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "pass"


# -- rd10b: a quoted `#` in a flow map does not truncate before `uses` ------- #
def test_quoted_hash_in_flow_map_does_not_hide_unpinned_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        'jobs:\n  b:\n    steps:\n'
        '      - { name: "Build #1", uses: actions/checkout@v4 }\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"  # v4 is unpinned


# -- rd10c: a `uses` in a bracketless flow *sequence* mapping is detected ---- #
def test_bracketless_flow_sequence_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps: [uses: actions/checkout@v4]\n", encoding="utf-8"
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd10d: a `uses` behind a YAML anchor node property is detected ---------- #
def test_anchored_flow_map_uses_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - &checkout { uses: actions/checkout@v4 }\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd10e: JSON inside a single-quoted flow `run:` value is not an action --- #
def test_single_quoted_run_json_in_flow_is_not_a_false_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - { run: 'echo {\"uses\":\"actions/evil@v1\"}' }\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd10f: a block scalar with an indent+chomp indicator is still skipped --- #
def test_block_scalar_with_indent_indicator_skips_body(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        "      - name: x\n        run: |2-\n          uses: not-an-action@v1\n"
        f"      - uses: actions/real@{sha}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd10g: an impossible handle (consecutive hyphens) is not a valid owner -- #
def test_codeowners_consecutive_hyphen_handle_is_invalid(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* @mona--cat\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "fail"


# -- rd10h: an email with an empty domain label is not a valid owner -------- #
def test_codeowners_empty_domain_label_email_is_invalid(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* user@foo..example.com\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "fail"


# ========================================================================== #
# Round-6 rubber-duck confirmation follow-ups (rd11): value-aware YAML scan   #
# ========================================================================== #

# -- rd11a: an unquoted `#` inside a flow-map step name does not hide `uses` - #
def test_bare_hash_in_flow_name_does_not_hide_unpinned_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - {name: Build#1, uses: actions/checkout@v4}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd11b: an apostrophe inside a flow-map value is not a string delimiter -- #
def test_apostrophe_in_flow_value_does_not_hide_unpinned_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - {name: don't, uses: actions/checkout@v4}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd11c: a `#suffix` glued to a ref is part of the ref, not a comment ----- #
def test_hash_suffixed_ref_is_not_treated_as_pinned(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: acme/action@{sha}#mutable\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd11d: a plain value ending in `:|` does not open a block scalar -------- #
def test_colon_pipe_plain_value_does_not_start_block_scalar(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - name: foo:|\n        uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd11e: a `uses:` substring inside a `run:` command is not an action ----- #
def test_uses_token_inside_run_command_is_not_a_false_action(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - run: echo --uses:actions/checkout@v4\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd11f: a value-side YAML anchor before a pinned ref still reads as pinned #
def test_value_side_anchor_before_sha_is_pinned(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: &checkout actions/checkout@{sha}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd11g: an email local part with consecutive dots is not a valid owner --- #
def test_codeowners_consecutive_dot_email_local_part_is_invalid(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("* a..b@example.com\n", encoding="utf-8")
    assert _co(audit_repository(tmp_path))["status"] == "fail"


# -- rd11h: a normal quoted pinned ref (no escapes) still reads as pinned ---- #
def test_double_quoted_sha_ref_is_pinned(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f'jobs:\n  b:\n    steps:\n      - uses: "actions/checkout@{sha}"\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# ========================================================================== #
# Round-7 rubber-duck confirmation follow-ups (rd12): compact / JSON flow     #
# ========================================================================== #

# -- rd12a: a compact JSON-style flow mapping is not missed ----------------- #
def test_compact_json_flow_mapping_unpinned_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        'jobs:\n  b:\n    steps:\n      - {"uses":"actions/checkout@v4"}\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"  # v4 unpinned


def test_compact_json_flow_mapping_pinned_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f'jobs:\n  b:\n    steps:\n      - {{"uses":"actions/checkout@{sha}"}}\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd12b: a YAML alias reusing an anchored pinned ref is not a false FAIL -- #
def test_yaml_alias_reuse_of_pinned_ref_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps: "
        f"[{{uses: &co actions/checkout@{sha}}}, {{uses: *co}}]\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd12c: a compact nested flow value does not corrupt the pinned ref ------ #
def test_compact_nested_flow_value_keeps_ref_clean(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - {{with:{{fetch-depth: 0}}, uses: actions/checkout@{sha}}}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd12d: the ref is split on the LAST @, so a path containing @ still pins - #
def test_ref_with_at_in_path_is_pinned_on_last_at(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: acme/ci/.github/workflows/build@v2.yml@{sha}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# ========================================================================== #
# Round-8 rubber-duck confirmation follow-ups (rd13): quoted-key flow + alias #
# resolution                                                                 #
# ========================================================================== #

# -- rd13a: a compact quoted key with a *plain* value is detected ----------- #
def test_compact_quoted_key_plain_value_unpinned_is_detected(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        'jobs:\n  b:\n    steps:\n      - {"uses":actions/checkout@v4}\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"  # v4 unpinned


def test_compact_quoted_key_plain_value_pinned_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f'jobs:\n  b:\n    steps:\n      - {{"uses":actions/checkout@{sha}}}\n',
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd13b: an anchor on a NON-`uses` key smuggled into `uses` via an alias -- #
# must not score as pinned; the alias resolves to nothing we scored, so it is
# reported verbatim and classified unpinned rather than silently skipped.
def test_alias_to_non_uses_anchor_is_not_a_false_pass(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        "      - {name: &ref actions/checkout@v4, uses: *ref}\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# -- rd13c: a block-style alias reusing an anchored *pinned* ref still passes - #
# (companion to rd12b, which used flow syntax): no false FAIL on legitimate
# DRY reuse of a SHA-pinned action across steps.
def test_block_alias_reuse_of_pinned_ref_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - uses: &co actions/checkout@{sha}\n"
        "      - uses: *co\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd13d: a dangling alias (no matching anchor) is conservatively unpinned -- #
def test_dangling_uses_alias_is_flagged(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - uses: *missing\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"


# ========================================================================== #
# Round-9 rubber-duck confirmation follow-ups (rd14): anchors on any value    #
# ========================================================================== #

# -- rd14a: a pinned ref centralised in `env:` and reused via an alias passes - #
# (anchors are collected from *any* mapping value, not only `uses:` values, so
# this common DRY pattern is not a false FAIL).
def test_alias_to_pinned_anchor_on_non_uses_value_passes(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "a" * 40
    (wf / "ci.yml").write_text(
        f"env:\n  CHECKOUT: &checkout actions/checkout@{sha}\n"
        "jobs:\n  b:\n    steps:\n      - uses: *checkout\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "pass"


# -- rd14b: a *mutable* ref anchored on a non-`uses` value still resolves to a - #
# FAIL when reused via an alias (the false-PASS protection is preserved).
def test_alias_to_mutable_anchor_on_non_uses_value_fails(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "env:\n  CHECKOUT: &checkout actions/checkout@v4\n"
        "jobs:\n  b:\n    steps:\n      - uses: *checkout\n",
        encoding="utf-8",
    )
    assert _act(audit_repository(tmp_path))["status"] == "fail"
