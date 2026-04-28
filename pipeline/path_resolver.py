"""Phase 1.5: resolve a patch's file path at an arbitrary historical tag.

The patched file may not exist at the target tag at its original path because:
  - the file was renamed (e.g. ffmpeg's libavformat/applehttp.c -> hls.c)
  - the file was moved across directories (qemu's usb-redir.c -> hw/usb/redirect.c)
  - the file was split or merged
  - the file's basename changed entirely

Layer-1 cross-file tracing decides whether the tag is in the candidate range,
but it does NOT produce a path mapping that the vuln_classifier can use to
read the file. This module fills that gap.

Strategy (in priority order):

  1. Exact path: try fp.path directly.
  2. Basename match: ls-tree the target tag, find files with the same basename;
     pick the one whose path components have the most overlap with fp.path.
  3. Identifier grep: extract high-confidence identifiers from the diff
     (function name from `@@` header, then long context lines, then long
     meaningful deleted lines). Grep each in the tree; score candidate files
     by total hits weighted by identifier specificity. Return the top file.
  4. Give up: return None — the file genuinely does not exist at this tag,
     either because the feature was not yet implemented or the GT is wrong.

The resolver returns a `ResolvedPath` containing the resolved path and a
confidence label so the caller can decide whether to fall through to LLM.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from vara.interface import FilePatch
from vara.repo import GitRepo
from vara.patch_parser import is_source_path
from pipeline.line_filter import is_meaningful_line


@dataclass
class ResolvedPath:
    path: Optional[str]
    confidence: str          # "exact" | "basename" | "grep" | "none" | "non_source"
    method: str              # human-readable description
    candidates: List[str]    # other candidates considered (for debugging)


# Non-source filtering is centralized in vara.patch_parser.is_source_path


# ---------------------------------------------------------------------------
# Identifier extraction
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}")
_FUNC_DECL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]+)\s*\(")


def _function_name_from_header(header: str) -> Optional[str]:
    """Extract a function name from a `@@ ... @@` hunk header context."""
    if not header:
        return None
    m = _FUNC_DECL_RE.search(header)
    if m:
        return m.group(1)
    return None


def _diff_identifiers(fp: FilePatch) -> List[Tuple[str, float]]:
    """Pull identifiers from the patch with rough specificity scores.

    Higher score = more discriminating (less likely to false-match in unrelated
    files). Function names from the @@ header are weighted highest, followed
    by long context lines, then long meaningful deleted lines.
    """
    out: List[Tuple[str, float]] = []
    seen: Set[str] = set()

    def add(token: str, score: float) -> None:
        if not token or token in seen:
            return
        seen.add(token)
        out.append((token, score))

    # Function names from hunk headers
    for hunk in fp.hunks:
        fname = _function_name_from_header(hunk.header_context)
        if fname and len(fname) >= 5:
            add(fname, 5.0)

    # Long context lines (high specificity — they're verbatim code)
    for hunk in fp.hunks:
        for ctx in hunk.context_lines:
            s = ctx.strip()
            if 20 <= len(s) <= 200:
                add(s, 3.0)

    # Long meaningful deleted lines
    for hunk in fp.hunks:
        for d in hunk.deleted_lines:
            if not is_meaningful_line(d):
                continue
            s = d.strip()
            if 20 <= len(s) <= 200:
                add(s, 2.0)

    # Function-call-like identifiers from any line, low score
    for hunk in fp.hunks:
        for line in list(hunk.deleted_lines) + list(hunk.context_lines):
            for tok in _FUNC_DECL_RE.findall(line):
                if len(tok) >= 6 and not tok.lower() in {"static", "return", "sizeof", "struct"}:
                    add(tok, 1.0)

    return out[:10]  # cap to keep grep-cost bounded


# ---------------------------------------------------------------------------
# Tree query helpers
# ---------------------------------------------------------------------------

def _ls_tree(repo: GitRepo, tag: str) -> List[str]:
    """List all files at the tag (cached on the repo object)."""
    if not hasattr(repo, "_ls_tree_cache"):
        repo._ls_tree_cache = {}  # type: ignore
    cache = repo._ls_tree_cache  # type: ignore
    if tag in cache:
        return cache[tag]
    try:
        out = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", tag],
            cwd=str(repo.path), capture_output=True, text=True, check=False,
        ).stdout
        files = out.splitlines()
    except Exception:
        files = []
    cache[tag] = files
    return files


def _path_overlap_score(target: str, candidate: str) -> int:
    """Number of trailing path components shared between target and candidate."""
    t = target.split("/")
    c = candidate.split("/")
    n = 0
    for a, b in zip(reversed(t), reversed(c)):
        if a == b:
            n += 1
        else:
            break
    return n


def _grep_count(repo: GitRepo, tag: str, needle: str, max_files: int = 5) -> List[str]:
    """Return up to max_files paths in `tag` that contain the literal needle.

    Limits common across grep variants make this O(scan).
    """
    try:
        out = subprocess.run(
            ["git", "grep", "-l", "-F", "--", needle, tag, "--"],
            cwd=str(repo.path), capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return []
    paths: List[str] = []
    for line in out.splitlines():
        if ":" in line:
            paths.append(line.split(":", 1)[1])
        if len(paths) >= max_files:
            break
    return paths


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_resolve_cache: Dict[str, ResolvedPath] = {}


def resolve_path(repo: GitRepo, fp: FilePatch, tag: str) -> ResolvedPath:
    """Find the file in `tag` that corresponds to the patch's file.

    Results are cached by (repo_path, target_path, tag) since the tree
    at a given tag is immutable.
    """
    target_path = fp.old_path or fp.new_path
    if not target_path:
        return ResolvedPath(None, "none", "no patch path", [])

    cache_key = f"{repo.path}:{target_path}:{tag}"
    if cache_key in _resolve_cache:
        return _resolve_cache[cache_key]

    result = _resolve_path_uncached(repo, fp, target_path, tag)
    _resolve_cache[cache_key] = result
    return result


def _resolve_path_uncached(
    repo: GitRepo, fp: FilePatch, target_path: str, tag: str,
) -> ResolvedPath:
    # Step 0: non-source files (docs, changelogs) carry no vuln signal
    if not is_source_path(target_path):
        return ResolvedPath(None, "non_source", f"filtered: {target_path}", [])

    # Step 1: exact path
    files = _ls_tree(repo, tag)
    file_set = set(files)
    if target_path in file_set:
        return ResolvedPath(target_path, "exact", "path exists at tag", [])

    # Step 2: basename match
    basename = os.path.basename(target_path)
    same_base = [f for f in files if os.path.basename(f) == basename]
    if len(same_base) == 1:
        return ResolvedPath(same_base[0], "basename", "unique basename match", same_base)
    if len(same_base) > 1:
        best = max(same_base, key=lambda c: _path_overlap_score(target_path, c))
        return ResolvedPath(best, "basename", f"best of {len(same_base)} same-basename files", same_base)

    # Step 3: identifier grep
    idents = _diff_identifiers(fp)
    if not idents:
        return ResolvedPath(None, "none", "no identifiers to grep", [])

    scores: Dict[str, float] = {}
    grepped: List[str] = []
    for token, weight in idents:
        hits = _grep_count(repo, tag, token, max_files=8)
        grepped.append(f"{token[:30]}->({len(hits)})")
        for h in hits:
            scores[h] = scores.get(h, 0.0) + weight

    if not scores:
        return ResolvedPath(None, "none", "no grep hits; " + " | ".join(grepped[:5]), [])

    # Prefer files with the same extension as the patch's file
    target_ext = os.path.splitext(target_path)[1]
    if target_ext:
        for path in list(scores.keys()):
            if os.path.splitext(path)[1] != target_ext:
                scores[path] *= 0.3  # heavy penalty for different extension

    best = max(scores.items(), key=lambda kv: kv[1])
    candidates_sorted = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return ResolvedPath(
        path=best[0],
        confidence="grep",
        method=f"grep top score {best[1]:.1f}; " + " | ".join(grepped[:5]),
        candidates=[c[0] for c in candidates_sorted[:5]],
    )
