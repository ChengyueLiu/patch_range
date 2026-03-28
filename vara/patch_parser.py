"""Parse git commit diffs into structured PatchInfo."""

from __future__ import annotations

import re
from typing import List

from vara.interface import PatchInfo, FilePatch, HunkChange
from vara.repo import GitRepo


def normalize_line(line: str) -> str:
    """Normalize a code line: strip whitespace, collapse spaces."""
    return re.sub(r'\s+', ' ', line.strip())


def parse_diff(diff_text: str) -> List[FilePatch]:
    """Parse unified diff text into a list of FilePatch objects."""
    file_patches = []
    current_file = None
    current_hunk = None

    for line in diff_text.splitlines():
        # New file header
        if line.startswith("diff --git"):
            if current_file is not None:
                if current_hunk and (current_hunk.deleted_lines or current_hunk.added_lines):
                    current_file.hunks.append(current_hunk)
                file_patches.append(current_file)
            current_file = FilePatch(old_path=None, new_path=None)
            current_hunk = None
            continue

        if current_file is None:
            continue

        # Parse old/new file paths
        if line.startswith("--- a/"):
            current_file.old_path = line[6:]
        elif line.startswith("--- /dev/null"):
            current_file.old_path = None
        elif line.startswith("+++ b/"):
            current_file.new_path = line[6:]
        elif line.startswith("+++ /dev/null"):
            current_file.new_path = None
        elif line.startswith("@@"):
            # New hunk
            if current_hunk and (current_hunk.deleted_lines or current_hunk.added_lines):
                current_file.hunks.append(current_hunk)
            current_hunk = HunkChange()
        elif current_hunk is not None:
            if line.startswith("-"):
                raw = line[1:]
                stripped = raw.strip()
                if stripped and not stripped.startswith("//") and not stripped.startswith("/*") and not stripped.startswith("*"):
                    current_hunk.deleted_lines.append(raw)
            elif line.startswith("+"):
                raw = line[1:]
                stripped = raw.strip()
                if stripped and not stripped.startswith("//") and not stripped.startswith("/*") and not stripped.startswith("*"):
                    current_hunk.added_lines.append(raw)
            else:
                # Context line
                if line.startswith(" "):
                    current_hunk.context_lines.append(line[1:])

    # Don't forget the last file/hunk
    if current_file is not None:
        if current_hunk and (current_hunk.deleted_lines or current_hunk.added_lines):
            current_file.hunks.append(current_hunk)
        file_patches.append(current_file)

    return file_patches


def parse_commits(repo: GitRepo, commit_hashes: List[str]) -> PatchInfo:
    """Parse one or more fixing commits into a PatchInfo."""
    all_file_patches = []
    for commit_hash in commit_hashes:
        diff_text = repo.get_diff(commit_hash)
        file_patches = parse_diff(diff_text)
        all_file_patches.extend(file_patches)

    return PatchInfo(
        commit_hashes=commit_hashes,
        file_patches=all_file_patches,
    )
