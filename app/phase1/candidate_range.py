"""Phase 1: build a high-recall candidate range of releases for one CVE.

Strategy: a release version *might* contain the bug only if the patched
files (or their cross-file ancestors) existed by then. We compute the
union of `git tag --contains <intro_commit>` across all introduction
commits, then subtract any tag containing **all** fixing commits.

Recall is ~93-100% on our 411-CVE benchmark; precision is intentionally
low (Phase 2 narrows it down).
"""

from __future__ import annotations

from typing import List, Set

from app.git_lib.interface import PatchInfo
from app.git_lib.repo import GitRepo
from app.phase1.tracing import find_file_introductions, trace_code_origin


def layer1(repo: GitRepo, patch: PatchInfo, release_tags: Set[str]) -> Set[str]:
    """Return the set of release tags that may contain the patched code.

    Args:
        repo: GitRepo wrapper for the project.
        patch: parsed fixing commits.
        release_tags: set of formal release tags (already filtered).

    Returns:
        Set of tags that (a) contain at least one introduction commit of any
        patched file, and (b) do NOT contain all fixing commits.
    """
    intro_commits: List[str] = []

    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue

        # File introductions across all branches
        file_intros = find_file_introductions(repo, path)
        intro_commits.extend(file_intros)

        # Cross-file migration: did this code live elsewhere first?
        if file_intros:
            earliest_intro = file_intros[-1]  # last = earliest

            # Try deleted lines as search anchors first; fall back to context lines
            old_intros: List[str] = []
            if fp.all_deleted_lines:
                old_intros = trace_code_origin(repo, path, earliest_intro, fp.all_deleted_lines)
            if not old_intros:
                context_lines = [l for hunk in fp.hunks for l in hunk.context_lines]
                if context_lines:
                    old_intros = trace_code_origin(repo, path, earliest_intro, context_lines)

            intro_commits.extend(old_intros)

    if not intro_commits:
        return set()

    # Union of tags containing any introduction commit (widest recall)
    candidates: Set[str] = set()
    for intro in set(intro_commits):
        candidates.update(repo.tags_containing(intro))

    # Subtract tags containing ALL fixing commits — partial fixes still count as vulnerable
    if patch.commit_hashes:
        fix_tag_sets = [repo.tags_containing(fc) for fc in patch.commit_hashes]
        fully_fixed = fix_tag_sets[0]
        for fts in fix_tag_sets[1:]:
            fully_fixed = fully_fixed & fts
        candidates -= fully_fixed

    return candidates & release_tags
