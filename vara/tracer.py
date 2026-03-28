"""Tracing-based approach: find affected versions via git blame and tag containment.

Strategy:
1. For each patched file, blame the deleted/context lines at fixing_commit~1
   to find the commit that introduced the vulnerable code.
2. Use `git tag --contains` to find all tags after the introducing commit.
3. Subtract tags that contain the fixing commit (already patched).
4. The remainder is the set of affected versions.
"""

from __future__ import annotations

import subprocess
from typing import List, Set, Optional

from vara.interface import PatchInfo, FilePatch
from vara.repo import GitRepo


def _blame_lines(repo: GitRepo, commit_parent: str, file_path: str,
                 lines: List[str]) -> List[str]:
    """Blame specific lines in a file at a given commit, return introducing commit hashes."""
    try:
        content = repo._run(["show", f"{commit_parent}:{file_path}"], check=True)
    except subprocess.CalledProcessError:
        return []

    content_lines = content.splitlines()
    introducing_commits = []

    for target in lines:
        target_stripped = target.strip()
        if not target_stripped:
            continue

        # Find line numbers that match
        for i, line in enumerate(content_lines):
            if line.strip() == target_stripped:
                line_num = i + 1
                try:
                    blame_out = repo._run(
                        ["blame", "-L", f"{line_num},{line_num}",
                         "--porcelain", commit_parent, "--", file_path],
                        check=True,
                    )
                    # First line of porcelain blame is: <hash> <orig_line> <final_line> <num_lines>
                    first_line = blame_out.splitlines()[0] if blame_out.strip() else ""
                    commit_hash = first_line.split()[0] if first_line else ""
                    if commit_hash and len(commit_hash) >= 7:
                        introducing_commits.append(commit_hash)
                except subprocess.CalledProcessError:
                    pass
                break  # Only blame the first match

    return introducing_commits


def _tags_containing(repo: GitRepo, commit: str) -> Set[str]:
    """Get all tags whose history contains the given commit (cached on repo)."""
    return repo.tags_containing(commit)


def trace_affected_versions(repo: GitRepo, patch: PatchInfo) -> List[str]:
    """Use tracing to find affected versions.

    For each fixing commit and each patched file:
    1. Blame deleted lines (or context lines for add-only) to find introducing commits
    2. Tags containing introducing commit but not fixing commit → affected
    """
    all_affected: Set[str] = set()

    for commit_hash in patch.commit_hashes:
        # Get parent commit
        try:
            parent = repo._run(
                ["rev-parse", commit_hash + "~1"], check=True
            ).strip()
        except subprocess.CalledProcessError:
            continue

        # Tags that contain the fix (should be excluded)
        fix_tags = _tags_containing(repo, commit_hash)

        for fp in patch.file_patches:
            if fp.old_path is None:
                continue

            # Prefer deleted lines for blame; fall back to context lines
            blame_targets = fp.all_deleted_lines
            if not blame_targets:
                blame_targets = [l for hunk in fp.hunks for l in hunk.context_lines]

            if not blame_targets:
                continue

            introducing = _blame_lines(repo, parent, fp.old_path, blame_targets)
            if not introducing:
                continue

            # Find the earliest introducing commit's tags
            for intro_commit in set(introducing):
                intro_tags = _tags_containing(repo, intro_commit)
                affected = intro_tags - fix_tags
                all_affected.update(affected)

    return sorted(all_affected)
