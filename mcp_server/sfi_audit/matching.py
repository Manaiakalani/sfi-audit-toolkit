"""Pattern matching helpers for the SFI scanner.

Checklist ``signals`` / ``anti_signals`` are a mix of literal tokens (config
keys and environment-variable names) and regular expressions (for example,
cloud access-key formats and PEM private-key headers). This module classifies
each token, compiles it appropriately, and provides a safe way to search text
while redacting any secret-looking values out of the evidence snippets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

# A token is treated as a regex if it contains regex metacharacters. A lone
# ``.`` (as in ``process.env.``) is deliberately NOT treated as a metacharacter
# so that dotted literals stay literal.
_REGEX_HINT = re.compile(
    r"\\[a-zA-Z]"          # escapes such as \s \d \w
    r"|\[[^\]]*\]"          # character classes [0-9A-Z]
    r"|\(\?[:=!iP<]"        # groups (?i) (?: (?= ...
    r"|\{\d+(?:,\d*)?\}"    # quantifiers {16} {1,3}
    r"|\|"                  # alternation
    r"|\)\?|\)\+|\)\*"      # quantified groups )? )+ )*
)

# Redaction: mask quoted values and values after '=' or ':' so evidence
# snippets never leak real secrets. Thresholds are deliberately low (6+) so
# short passwords/keys/tokens are still masked; for a security tool the safe
# direction is to over-redact rather than leak.
# The two quoted-value branches are kept *disjoint* (a backslash escape via
# ``\\.`` XOR any other non-quote, non-backslash character) so the pattern is
# linear and cannot catastrophically backtrack on a crafted run of backslashes.
_QUOTED = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\]){6,})\1""")
_ASSIGNED = re.compile(r"([=:]\s*)([^\s\"'`,;]{6,})")
_REDACTION = "\u00abredacted\u00bb"  # «redacted»
_MAX_SNIPPET = 200
# Hard cap on the line length fed to the redaction regex battery. Anything
# beyond it is dropped *before* matching (it is never displayed, so it cannot
# leak) which bounds redaction cost to O(_MAX_LINE) per line regardless of input.
_MAX_LINE = 2000
# Upper bound on the line length fed to a *regex* signal/anti-signal search, so a
# pathological very long single line cannot drive super-linear backtracking in a
# KB-authored pattern. Real markers occur near the start of a line.
_MAX_REGEX_LINE = 20000

# Standalone secret formats that can appear unquoted and without an '='/':'
# assignment. These are masked wherever they occur so evidence never leaks a
# real credential, even when it is a bare token on its own.
_SECRET_PATTERNS = [
    # Redact the marker *and the rest of the physical line* so a PEM key that
    # has been flattened onto one line (literal ``\n`` separators, i.e. no real
    # newline character) never leaks its base64 body after the header is masked.
    re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----[^\n]*"),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{12,}\b"),
    re.compile(r"\bgh[opsur]_[A-Za-z0-9]{20,}\b"),          # GitHub PAT/OAuth/app tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),         # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),              # Google API key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                  # OpenAI-style
    re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}"),  # JWT
]
# A bearer token may be standard base64 (``/`` ``+`` ``=``) or base64url, so the
# value class includes those characters; the whole token after ``Bearer`` is
# masked rather than only its leading url-safe run.
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-/+=]{8,}")

# Key-aware redaction. When a *secret-bearing key* appears, the associated value
# is masked in full regardless of its shape or length — covering unquoted,
# short, space-delimited, and XML-wrapped values that the generic value matchers
# above deliberately miss (to avoid clobbering ordinary short config values).
# Over-redaction here is acceptable; leaking a credential is not. Bare "key"/
# "token" are intentionally excluded to avoid masking innocuous config keys.
_SECRET_WORDS = (
    r"(?:passwords?|passwd|pwd|passphrase|secret|"
    r"client[_\-]?secret|api[_\-]?key|access[_\-]?key|secret[_\-]?key|"
    r"private[_\-]?key|encryption[_\-]?key|"
    r"auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|sas[_\-]?token|"
    r"connection[_\-]?string)"
)
# ``key: value`` / ``key = value`` (config assignment). The value is masked to
# end of line so a value that itself contains ``#`` cannot leak a trailing piece.
_KV_SECRET = re.compile(
    r"(?i)([A-Za-z0-9_.\[\]\"'`-]*" + _SECRET_WORDS
    + r"[A-Za-z0-9_.\"'`\-]*\s*[:=]\s*)(\S.*)$"
)
# ``<element ...>value</element>`` — mask the XML/HTML element's text content.
_XML_SECRET = re.compile(
    r"(?i)(<\s*[A-Za-z0-9:._-]*" + _SECRET_WORDS
    + r"[A-Za-z0-9:._-]*[^>]*>)([^<\n]+)"
)
# ``setx NAME value`` (Windows) — whitespace-delimited env-var assignment, with
# an optional flag such as ``/M`` before the variable name. The value is masked
# to end of line (not just the first token) so a quoted multi-word value such as
# ``setx SECRET "alpha bravo charlie"`` cannot leak its tail after the opening
# quote is consumed.
_SETX_SECRET = re.compile(
    r"(?i)(\bsetx\s+(?:/[A-Za-z]\s+)?[A-Za-z0-9_]*" + _SECRET_WORDS
    + r"[A-Za-z0-9_]*\s+)(\S.*)$"
)

# AWS *secret* access keys are 40-character base64-ish strings with no fixed
# prefix, so they are too generic to redact everywhere without clobbering
# hashes and IDs. We therefore only mask a bare 40-char token when the same
# line also carries an AWS access-key ID or an "aws ... secret/access key"
# context — the situation in which the token is almost certainly the secret.
_AWS_ID_HINT = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{12,}\b")
_AWS_SECRET_CTX = re.compile(r"(?i)aws[^\n]{0,32}(?:secret|access)[^\n]{0,16}key")
_AWS_SECRET_VALUE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def looks_like_regex(token: str) -> bool:
    return bool(_REGEX_HINT.search(token))


@dataclass
class Matcher:
    token: str
    mode: str  # "regex" | "literal"
    regex: Optional[re.Pattern] = None
    needle: Optional[str] = None


def build_matcher(token: str) -> Matcher:
    """Compile a signal/anti-signal token into a :class:`Matcher`."""
    if looks_like_regex(token):
        try:
            return Matcher(token=token, mode="regex", regex=re.compile(token))
        except re.error:
            pass  # malformed regex -> fall back to a literal substring search
    return Matcher(token=token, mode="literal", needle=token.lower())


def search_line(matcher: Matcher, line: str, line_lower: str) -> Optional[Tuple[int, int]]:
    """Return the ``(start, end)`` span of the first match on ``line`` or None."""
    if matcher.mode == "literal":
        assert matcher.needle is not None
        idx = line_lower.find(matcher.needle)
        if idx >= 0:
            return idx, idx + len(matcher.needle)
        return None
    assert matcher.regex is not None
    # Bound the input to a regex search: a pathological very long single line
    # could otherwise drive super-linear backtracking in a KB-authored pattern.
    # Only truthiness of the result is used downstream, and real markers occur
    # near the start of a line, so searching a generous prefix is sufficient.
    target = line if len(line) <= _MAX_REGEX_LINE else line[:_MAX_REGEX_LINE]
    found = matcher.regex.search(target)
    if found:
        return found.start(), found.end()
    return None


def redact(line: str) -> str:
    """Mask secret-looking values and trim a line for safe display."""
    # Drop anything past the hard cap up front: it is never displayed (so it
    # cannot leak) and this bounds the cost of every regex below to O(_MAX_LINE).
    masked = line[:_MAX_LINE]
    aws_context = bool(_AWS_ID_HINT.search(masked) or _AWS_SECRET_CTX.search(masked))
    for pat in _SECRET_PATTERNS:
        masked = pat.sub(_REDACTION, masked)
    masked = _BEARER.sub(lambda m: f"{m.group(1)} {_REDACTION}", masked)
    if aws_context:
        masked = _AWS_SECRET_VALUE.sub(_REDACTION, masked)
    # Key-aware masking runs before the generic value matchers so it can claim
    # the whole (possibly short/space-delimited/XML) value first.
    masked = _KV_SECRET.sub(lambda m: f"{m.group(1)}{_REDACTION}", masked)
    masked = _XML_SECRET.sub(lambda m: f"{m.group(1)}{_REDACTION}", masked)
    masked = _SETX_SECRET.sub(lambda m: f"{m.group(1)}{_REDACTION}", masked)
    masked = _QUOTED.sub(lambda m: f"{m.group(1)}{_REDACTION}{m.group(1)}", masked)
    masked = _ASSIGNED.sub(lambda m: f"{m.group(1)}{_REDACTION}", masked)
    masked = masked.strip()
    if len(masked) > _MAX_SNIPPET:
        masked = masked[:_MAX_SNIPPET] + "\u2026"
    return masked


def build_matchers(tokens: List[str]) -> List[Matcher]:
    return [build_matcher(t) for t in tokens]
