"""File-introduction tracing for Phase 1.

Two functions:
  - find_file_introductions(repo, file_path): all commits that ADDED this
    file across any branch. Falls back to earliest touching commit if
    git records the creation as Modify (e.g. when a file was split off).
  - trace_code_origin(repo, file_path, file_intro_commit, search_lines):
    if the patched code already existed in another file before this file
    was created, return that older file's introduction commits. Recursive
    up to max_depth=3 to handle multi-step migrations.

Both are module-level cached because the same files come up repeatedly
across a CVE batch.
"""

from __future__ import annotations

import re
import subprocess
from typing import Dict, List

from app.git_lib.repo import GitRepo


_file_intro_cache: Dict[str, Dict[str, List[str]]] = {}     # repo_path -> {file -> [commits]}
_trace_origin_cache: Dict[str, List[str]] = {}              # "repo:file:commit" -> results


def find_file_introductions(repo: GitRepo, file_path: str) -> List[str]:
    """All commits that introduced this file across any branch (cached)."""
    repo_key = str(repo.path)
    if repo_key not in _file_intro_cache:
        _file_intro_cache[repo_key] = {}
    cache = _file_intro_cache[repo_key]

    if file_path in cache:
        return cache[file_path]

    try:
        output = repo._run(
            ["log", "--all", "--diff-filter=A", "--format=%H", "--", file_path],
            check=True,
        )
        result = [c.strip() for c in output.splitlines() if c.strip()]
    except subprocess.CalledProcessError:
        result = []

    # Fallback: --diff-filter=A misses files created via split/copy (recorded
    # as Modify). Use the earliest touching commit instead.
    if not result:
        try:
            output = repo._run(
                ["log", "--all", "--reverse", "--format=%H", "-1", "--", file_path],
                check=True,
            )
            first = output.strip()
            if first:
                result = [first]
        except subprocess.CalledProcessError:
            pass

    cache[file_path] = result
    return result


def trace_code_origin(
    repo: GitRepo,
    file_path: str,
    file_intro_commit: str,
    search_lines: List[str],
    depth: int = 0,
    max_depth: int = 3,
) -> List[str]:
    """Detect cross-file code migration.

    Checks (at file_intro_commit's parent) whether any of the search_lines
    already exist in some other file. If so, returns that file's introduction
    commits — recursively (up to max_depth) so we follow migration chains
    like A.c → B.c → C.c.
    """
    cache_key = f"{repo.path}:{file_path}:{file_intro_commit}"
    if cache_key in _trace_origin_cache:
        return _trace_origin_cache[cache_key]

    try:
        parent = repo._run(["rev-parse", file_intro_commit + "~1"], check=True).strip()
    except subprocess.CalledProcessError:
        _trace_origin_cache[cache_key] = []
        return []

    results: List[str] = []
    for line in search_lines:
        stripped = line.strip()
        if not stripped or len(stripped) < 10:
            continue

        candidates = [stripped]
        tokens = re.split(r'[\s=(,;]+', stripped)
        for tok in tokens:
            if len(tok) >= 10 and not tok.startswith(('if', 'for', 'while', 'return')):
                candidates.append(tok)

        for pattern in candidates:
            try:
                r = subprocess.run(
                    ["git", "grep", "-l", "--fixed-strings", pattern, parent, "--"],
                    cwd=str(repo.path), capture_output=True, text=True,
                )
                if r.returncode == 0 and r.stdout.strip():
                    old_file = r.stdout.strip().splitlines()[0].split(":", 1)[1]
                    old_intros = find_file_introductions(repo, old_file)
                    results.extend(old_intros)
                    if old_intros and depth < max_depth:
                        deeper = trace_code_origin(
                            repo, old_file, old_intros[-1], search_lines,
                            depth=depth + 1, max_depth=max_depth,
                        )
                        results.extend(deeper)
                    _trace_origin_cache[cache_key] = results
                    return results
            except Exception:
                continue

    _trace_origin_cache[cache_key] = results
    return results
