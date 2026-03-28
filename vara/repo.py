"""Git repository operations."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional


class GitRepo:
    """Wrapper for git operations on a local repository."""

    def __init__(self, repo_path: str):
        self.path = Path(repo_path).resolve()

    def _run(self, args: List[str], check: bool = True) -> str:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(self.path),
            capture_output=True,
            text=True,
            check=check,
        )
        return result.stdout

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
