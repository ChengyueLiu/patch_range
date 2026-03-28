"""Git repository operations."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Set


class GitRepo:
    """Wrapper for git operations on a local repository."""

    def __init__(self, repo_path: str):
        self.path = Path(repo_path).resolve()
        self._file_list_cache: Dict[str, List[str]] = {}
        self._tag_commit_cache: Optional[Dict[str, str]] = None  # tag -> commit hash
        self._tags_containing_cache: Dict[str, Set[str]] = {}  # commit -> set of tags

    def _run(self, args: List[str], check: bool = True) -> str:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(self.path),
            capture_output=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args)
        return result.stdout.decode("utf-8", errors="replace")

    def get_all_tags(self) -> List[str]:
        """Return all tags in the repository."""
        output = self._run(["tag", "--list"])
        return [t.strip() for t in output.splitlines() if t.strip()]

    def get_diff(self, commit_hash: str) -> str:
        """Get the unified diff of a commit."""
        return self._run(["diff", commit_hash + "~1", commit_hash, "--"])

    def get_file_at_version(self, tag: str, file_path: str) -> Optional[str]:
        """Get file content at a specific tag. Returns None if file doesn't exist."""
        try:
            return self._run(["show", f"{tag}:{file_path}"], check=True)
        except subprocess.CalledProcessError:
            return None

    def find_file_at_version(self, tag: str, file_path: str) -> Optional[str]:
        """Find a file at a version, trying the original path first, then searching by filename.

        Returns the content if found, None otherwise.
        """
        # Try original path first
        content = self.get_file_at_version(tag, file_path)
        if content is not None:
            return content

        # Search by filename
        target_name = os.path.basename(file_path)
        file_list = self._get_file_list(tag)

        candidates = [f for f in file_list if os.path.basename(f) == target_name]
        if len(candidates) == 1:
            return self.get_file_at_version(tag, candidates[0])

        # Multiple candidates: pick the one with the most similar path
        if len(candidates) > 1:
            best = self._best_path_match(file_path, candidates)
            return self.get_file_at_version(tag, best)

        return None

    def _get_file_list(self, tag: str) -> List[str]:
        """Get all file paths at a given tag (cached)."""
        if tag not in self._file_list_cache:
            try:
                output = self._run(["ls-tree", "-r", "--name-only", tag], check=True)
                self._file_list_cache[tag] = output.splitlines()
            except subprocess.CalledProcessError:
                self._file_list_cache[tag] = []
        return self._file_list_cache[tag]

    @staticmethod
    def _best_path_match(target: str, candidates: List[str]) -> str:
        """Pick the candidate with the most path components in common with target."""
        target_parts = target.split("/")

        def score(candidate: str) -> int:
            parts = candidate.split("/")
            # Count common suffix components (from filename backwards)
            common = 0
            for t, c in zip(reversed(target_parts), reversed(parts)):
                if t == c:
                    common += 1
                else:
                    break
            return common

        return max(candidates, key=score)

    def _get_tag_commits(self) -> Dict[str, str]:
        """Get a mapping of tag -> commit hash (cached)."""
        if self._tag_commit_cache is None:
            output = self._run(
                ["for-each-ref", "--format=%(refname:short) %(objectname)", "refs/tags"],
                check=True,
            )
            self._tag_commit_cache = {}
            for line in output.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    tag, commit = parts
                    # Dereference annotated tags to their commit
                    try:
                        dereffed = self._run(
                            ["rev-parse", f"{tag}^{{commit}}"], check=True
                        ).strip()
                        self._tag_commit_cache[tag] = dereffed
                    except subprocess.CalledProcessError:
                        self._tag_commit_cache[tag] = commit
        return self._tag_commit_cache

    def tags_containing(self, commit: str) -> Set[str]:
        """Get all tags that contain the given commit (cached)."""
        if commit in self._tags_containing_cache:
            return self._tags_containing_cache[commit]

        try:
            output = self._run(["tag", "--contains", commit], check=True)
            result = set(t.strip() for t in output.splitlines() if t.strip())
        except subprocess.CalledProcessError:
            result = set()

        self._tags_containing_cache[commit] = result
        return result
