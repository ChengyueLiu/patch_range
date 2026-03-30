"""Git repository operations."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Set


class GitRepo:
    """Wrapper for git operations on a local repository."""

    def __init__(self, repo_path: str, cache_dir: str = "data/cache"):
        self.path = Path(repo_path).resolve()
        self._file_list_cache: Dict[str, List[str]] = {}
        self._tag_commit_cache: Optional[Dict[str, str]] = None
        self._tags_containing_cache: Dict[str, Set[str]] = {}

        # Disk cache for tags_containing
        repo_name = self.path.name
        self._disk_cache_path = Path(cache_dir) / repo_name / "tags_containing.json"
        self._load_disk_cache()

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

    def batch_get_files(self, requests: List[tuple]) -> Dict[tuple, Optional[str]]:
        """Batch read multiple (tag, file_path) pairs in one git process.

        Uses `git cat-file --batch` for efficiency.
        Returns dict of (tag, file_path) -> content or None.
        """
        if not requests:
            return {}

        proc = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=str(self.path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        results = {}
        # Feed all requests
        input_data = "\n".join(f"{tag}:{path}" for tag, path in requests) + "\n"
        stdout, _ = proc.communicate(input_data.encode("utf-8"))

        # Parse output
        pos = 0
        data = stdout
        for tag, path in requests:
            # Each response is either:
            #   "<object> <type> <size>\n<content>\n"
            # or:
            #   "<ref> missing\n"
            line_end = data.index(b"\n", pos)
            header = data[pos:line_end].decode("utf-8", errors="replace")

            if header.endswith("missing"):
                results[(tag, path)] = None
                pos = line_end + 1
            else:
                parts = header.split()
                size = int(parts[2])
                content_start = line_end + 1
                content_end = content_start + size
                content = data[content_start:content_end].decode("utf-8", errors="replace")
                results[(tag, path)] = content
                pos = content_end + 1  # skip trailing newline

        return results

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
        """Get all tags that contain the given commit (memory + disk cached)."""
        if commit in self._tags_containing_cache:
            return self._tags_containing_cache[commit]

        try:
            output = self._run(["tag", "--contains", commit], check=True)
            result = set(t.strip() for t in output.splitlines() if t.strip())
        except subprocess.CalledProcessError:
            result = set()

        self._tags_containing_cache[commit] = result
        self._disk_cache_dirty = True
        return result

    def flush_cache(self):
        """Write cache to disk if there are new entries."""
        if getattr(self, '_disk_cache_dirty', False):
            self._save_disk_cache()
            self._disk_cache_dirty = False

    def _load_disk_cache(self):
        """Load tags_containing cache from disk."""
        if self._disk_cache_path.exists():
            try:
                with open(self._disk_cache_path) as f:
                    data = json.load(f)
                self._tags_containing_cache = {k: set(v) for k, v in data.items()}
            except (json.JSONDecodeError, IOError):
                self._tags_containing_cache = {}

    def _save_disk_cache(self):
        """Save tags_containing cache to disk."""
        self._disk_cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: sorted(v) for k, v in self._tags_containing_cache.items()}
        try:
            with open(self._disk_cache_path, "w") as f:
                json.dump(data, f)
        except IOError:
            pass
