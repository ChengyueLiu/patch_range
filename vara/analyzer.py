"""VARA public API.

Two-channel approach for maximum recall:
1. Matching: check each version tag for vulnerability indicators
2. Tracing: blame vulnerable lines to find introducing commit, infer affected range
Result = union of both channels.
"""

from __future__ import annotations

from typing import List, Dict

from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from vara.matcher import find_affected_versions
from vara.tracer import trace_affected_versions

# Global repo cache: reuse GitRepo instances across CVEs for the same repo.
# This preserves the tags_containing cache across calls.
_repo_cache: Dict[str, GitRepo] = {}


def _get_repo(repo_path: str) -> GitRepo:
    """Get or create a cached GitRepo instance."""
    if repo_path not in _repo_cache:
        _repo_cache[repo_path] = GitRepo(repo_path)
    return _repo_cache[repo_path]


def analyze(repo_path: str, commits: List[str]) -> List[str]:
    """Analyze a repo and return affected version tags.

    Args:
        repo_path: Path to the git repository.
        commits: List of fixing commit hashes.

    Returns:
        List of version tags that are affected by the vulnerability.
    """
    repo = _get_repo(repo_path)
    patch = parse_commits(repo, commits)

    if not patch.file_patches:
        return []

    tags = repo.get_all_tags()

    # Channel 1: Matching
    match_results = find_affected_versions(repo, patch, tags)
    matched = set(r.version for r in match_results if r.is_affected)

    # Channel 2: Tracing
    traced = set(trace_affected_versions(repo, patch))

    # Union
    return sorted(matched | traced)
