"""VARA public API."""

from __future__ import annotations

from typing import List

from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from vara.matcher import find_affected_versions


def analyze(repo_path: str, commits: List[str]) -> List[str]:
    """Analyze a repo and return affected version tags.

    Args:
        repo_path: Path to the git repository.
        commits: List of fixing commit hashes.

    Returns:
        List of version tags that are affected by the vulnerability.
    """
    repo = GitRepo(repo_path)
    patch = parse_commits(repo, commits)

    if not patch.file_patches:
        return []

    tags = repo.get_all_tags()
    results = find_affected_versions(repo, patch, tags)
    return [r.version for r in results if r.is_affected]
