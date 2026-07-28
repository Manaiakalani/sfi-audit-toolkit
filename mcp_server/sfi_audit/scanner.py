"""Read-only heuristic scanner that audits a repository against SFI checklists.

The scanner walks a target directory, reads text files, and evaluates every
SFI checklist criterion against the file contents using the criterion's
``signals`` (positive control evidence) and ``anti_signals`` (likely
violations). It never writes to the target and redacts secret-looking values
out of the evidence it reports.

Per-criterion status:

* ``fail``   — at least one anti-signal matched (a likely violation).
* ``pass``   — a positive signal matched and no anti-signal did (automated
  evidence the control is present; not a guarantee of correctness).
* ``manual`` — no automated signal matched; a human must verify (common for
  policy/tenant-level controls that are not visible in source).
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import knowledge
from .checks import run_structural_checks
from .matching import build_matchers, redact, search_line

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vs",
    ".vscode", "bin", "obj", "target", ".gradle", ".terraform", "coverage",
    ".next", ".nuxt", ".cache", "vendor", ".tox", ".eggs", "site-packages",
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".o", ".a", ".lib",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".flac", ".psd", ".ai", ".sketch", ".pyc", ".pyd", ".wasm",
    ".db", ".sqlite", ".parquet", ".pkl", ".npy", ".onnx",
}

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 60_000_000
MAX_HITS_PER_KIND = 25

SEVERITY_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_scannable(fpath: Path) -> Optional[Tuple[int, Optional[str]]]:
    """Classify a candidate file for *content* scanning.

    Returns one of:

    * ``None`` — out of scope for content scanning (binary by extension or by
      NUL-byte content). The caller still counts the file's *name* for
      presence/absence checks; its absence from the content view is expected and
      does **not** make the scan incomplete.
    * ``(size, None)`` — the file is in scope (text) but its content was
      **skipped** because it is oversized or could not be read. The caller marks
      the audit ``truncated`` and counts it as skipped, so an absence-based
      ``pass`` is never silently based on text that was never scanned.
    * ``(size, text)`` — a readable UTF-8 text file whose content should be
      scanned.
    """
    if fpath.suffix.lower() in BINARY_EXTS:
        return None  # out of scope by extension
    try:
        size = fpath.stat().st_size
    except OSError:
        return 0, None  # in scope by name, metadata unreadable -> skipped
    try:
        with fpath.open("rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return size, None  # unreadable -> in-scope skipped
    if b"\x00" in chunk:
        return None  # binary content -> out of scope
    if size > MAX_FILE_BYTES:
        return size, None  # oversized text -> in-scope skipped
    try:
        text = fpath.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return size, None  # unreadable text -> in-scope skipped
    return size, text


def _norm_exclude(p: str) -> str:
    p = p.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/").casefold()


def _is_excluded(rel: str, excludes: Sequence[str]) -> bool:
    # Case-insensitive with ``./`` and backslash normalization so an exclude
    # cannot be bypassed by path-separator or letter-case differences on Windows.
    rel_cf = rel.replace("\\", "/").casefold()
    for e in excludes:
        e = _norm_exclude(e)
        if e and (rel_cf == e or rel_cf.startswith(e + "/")):
            return True
    return False


def _is_reparse_point(path: Path) -> bool:
    """True for symlinks (POSIX) and reparse points such as NTFS junctions /
    mount points (Windows), so a walk can never escape the repository via a
    link that ``Path.is_symlink()`` alone would not catch."""
    try:
        st = path.lstat()
    except OSError:
        return True  # unreadable -> treat as unsafe and skip
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def _iter_candidates(
    root: Path, excludes: Sequence[str]
) -> Iterable[Tuple[str, Path]]:
    """Yield ``(relative_path, absolute_path)`` for every non-pruned file under
    ``root`` (names only, no size/binary filtering). Prunes ignored dirs,
    excludes, and reparse points, and enforces the repository boundary so
    presence checks see files that content scanning skips (oversized/binary)."""
    for dirpath, dirnames, filenames in os.walk(root):
        reldir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        reldir = "" if reldir == "." else reldir
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORE_DIRS
            and not _is_excluded(f"{reldir}/{d}".lstrip("/"), excludes)
            and not _is_reparse_point(Path(dirpath) / d)
        ]
        for name in filenames:
            rel = f"{reldir}/{name}".lstrip("/")
            if _is_excluded(rel, excludes):
                continue
            fpath = Path(dirpath) / name
            if _is_reparse_point(fpath) or not _within_root(fpath, root):
                continue  # never follow links outside the repository boundary
            yield rel, fpath


def iter_repo_files(
    root: Path, excludes: Sequence[str] = (), stats: Optional[Dict[str, Any]] = None
) -> Iterable[Tuple[str, str]]:
    """Yield ``(relative_path, text)`` for scannable text files under ``root``.

    When ``stats`` is provided, ``stats['truncated']`` is set True if a scan cap
    (file count or total bytes) stops the walk early, so callers can surface that
    absence-based checks may be incomplete."""
    count = 0
    total = 0
    for rel, fpath in _iter_candidates(root, excludes):
        got = _read_scannable(fpath)
        if got is None:
            continue
        size, text = got
        if text is None:
            # In-scope text we could not fully read (oversized/unreadable): honour
            # the ``Tuple[str, str]`` contract by not yielding a None body, and flag
            # the walk as incomplete so absence-based callers don't over-trust it.
            if stats is not None:
                stats["truncated"] = True
            continue
        count += 1
        total += size
        yield rel, text
        if count >= MAX_FILES or total >= MAX_TOTAL_BYTES:
            if stats is not None:
                stats["truncated"] = True
            return


def _normalize_pillars(
    pillars: Optional[Sequence[Union[int, str]]]
) -> Optional[set]:
    if not pillars:
        return None
    slugs = set()
    unknown = []
    for p in pillars:
        target = knowledge.get_pillar(p)
        if target is None:
            unknown.append(str(p))
        else:
            slugs.add(target["slug"])
    if unknown:
        valid = sorted({c["pillar_slug"] for c in knowledge.get_checklist()})
        raise ValueError(
            "Unknown pillar(s): " + ", ".join(unknown)
            + ". Use pillar numbers 1-6 or one of: " + ", ".join(valid)
        )
    return slugs


def _prepare_criteria(slugs: Optional[set]) -> List[Dict[str, Any]]:
    criteria = []
    for c in knowledge.get_checklist():
        if slugs is not None and c["pillar_slug"] not in slugs:
            continue
        criteria.append(
            {
                "meta": c,
                "signal_matchers": build_matchers(c.get("signals", [])),
                "anti_matchers": build_matchers(c.get("anti_signals", [])),
            }
        )
    return criteria


def _blank_result(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": meta["id"],
        "pillar_id": meta["pillar_id"],
        "pillar_slug": meta["pillar_slug"],
        "requirement": meta["requirement"],
        "severity": meta.get("severity", "medium"),
        "how_to_verify": meta.get("how_to_verify", ""),
        "source_url": meta.get("source_url", ""),
        "status": "manual",
        "confidence": "n/a",
        "signal_hits": [],
        "anti_signal_hits": [],
    }


def _apply_matchers(
    matchers,
    lines: List[str],
    lowers: List[str],
    rel: str,
    bucket: List[Dict[str, Any]],
) -> bool:
    """Append hits for the first matching line of each matcher. Returns True if
    any regex-mode matcher hit (used to raise confidence)."""
    regex_hit = False
    for m in matchers:
        if len(bucket) >= MAX_HITS_PER_KIND:
            break
        for i, line in enumerate(lines):
            if search_line(m, line, lowers[i]) is not None:
                bucket.append(
                    {
                        "pattern": m.token,
                        "mode": m.mode,
                        "file": rel,
                        "line": i + 1,
                        "snippet": redact(line),
                    }
                )
                if m.mode == "regex":
                    regex_hit = True
                break
    return regex_hit


def audit_repository(
    path: Union[str, Path],
    pillars: Optional[Sequence[Union[int, str]]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Audit ``path`` against the SFI checklist and return structured results."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    excludes = tuple(exclude or ())
    slugs = _normalize_pillars(pillars)
    criteria = _prepare_criteria(slugs)
    results: Dict[str, Dict[str, Any]] = {
        c["meta"]["id"]: _blank_result(c["meta"]) for c in criteria
    }
    regex_confidence: Dict[str, bool] = {cid: False for cid in results}

    # One walk feeds both views, so ``files`` (content-scanned) is always a
    # subset of ``all_paths`` (every candidate name). ``all_paths`` keeps
    # collecting names for presence/absence checks even after the content cap is
    # reached, and any cap flips ``truncated`` so the scorecard can flag that
    # absence-based ``pass`` results (and the score) may be incomplete.
    files: List[Tuple[str, str]] = []
    scanned = 0
    skipped = 0
    total_bytes = 0
    content_full = False
    stats: Dict[str, Any] = {"truncated": False}
    all_paths: List[str] = []
    for rel, fpath in _iter_candidates(root, excludes):
        if len(all_paths) >= MAX_FILES * 2:
            stats["truncated"] = True  # too many files to even enumerate names
            break
        all_paths.append(rel)
        if content_full:
            continue  # keep enumerating names, but stop reading file contents
        got = _read_scannable(fpath)
        if got is None:
            continue  # binary/out-of-scope: name already counted above
        size, text = got
        if text is None:
            # In-scope text whose content we could not fully read (oversized or
            # unreadable): an absence-based ``pass`` must not trust this file, so
            # surface it as an incomplete scan rather than skipping it silently.
            stats["truncated"] = True
            skipped += 1
            continue
        files.append((rel, text))
        scanned += 1
        total_bytes += size
        lines = text.splitlines()
        lowers = [ln.lower() for ln in lines]
        for c in criteria:
            res = results[c["meta"]["id"]]
            rh1 = _apply_matchers(c["signal_matchers"], lines, lowers, rel, res["signal_hits"])
            rh2 = _apply_matchers(c["anti_matchers"], lines, lowers, rel, res["anti_signal_hits"])
            if rh1 or rh2:
                regex_confidence[c["meta"]["id"]] = True
        if scanned >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
            content_full = True
            stats["truncated"] = True  # content view is incomplete

    for cid, res in results.items():
        if res["anti_signal_hits"]:
            res["status"] = "fail"
        elif res["signal_hits"]:
            res["status"] = "pass"
        else:
            res["status"] = "manual"
        if res["status"] != "manual":
            res["confidence"] = "high" if regex_confidence[cid] else "medium"

    ordered = sorted(results.values(), key=lambda r: (r["pillar_id"], r["id"]))

    # Structural checks add precise findings that are hard to express as signals.
    # They receive ``all_paths`` (every candidate file name, including oversized
    # or binary files that content scanning skips) so presence/absence checks
    # cannot be fooled by, e.g., a tracked >1MB .env file.
    structural = run_structural_checks(root, files, all_paths)
    if slugs is not None:
        structural = [s for s in structural if s["pillar_slug"] in slugs]
    ordered.extend(structural)

    return {
        "repository": str(root),
        "generated_at": _now(),
        "kb_version": knowledge.kb_version(),
        "scanned": {
            "files": scanned,
            "files_seen": len(all_paths),
            "files_skipped": skipped,
            "pillars": sorted(slugs) if slugs else "all",
            "excluded": list(excludes),
            "truncated": stats["truncated"],
        },
        "results": ordered,
    }
