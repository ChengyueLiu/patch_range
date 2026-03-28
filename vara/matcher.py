"""High-recall matcher: check if a version is affected by a vulnerability.

Strategy for maximum recall:
A version is considered affected if ANY of these conditions hold for ANY patched file:
  1. At least one deleted line (vulnerable code) is found in the file
  2. At least one added line (fix code) is NOT found in the file
  3. The file does not exist (if it was modified, not newly created)

This is intentionally loose to maximize recall. Precision will be addressed in phase 2.
"""

from __future__ import annotations

import re
from typing import List

from vara.interface import PatchInfo, FilePatch, VersionResult, FileMatchResult
from vara.repo import GitRepo


def normalize(line: str) -> str:
    """Normalize a line for fuzzy comparison: collapse whitespace, strip."""
    return re.sub(r'\s+', ' ', line.strip())


def match_file_against_version(
    repo: GitRepo,
    file_patch: FilePatch,
    tag: str,
) -> FileMatchResult:
    """Check if a single file in a version shows signs of the vulnerability."""
    file_path = file_patch.old_path or file_patch.new_path

    # File was newly added in the fix → older versions won't have it,
    # but that doesn't mean they're affected by this file
    if file_patch.old_path is None:
        return FileMatchResult(
            file_path=file_path,
            found=False,
            vulnerable_lines_matched=0,
            vulnerable_lines_total=0,
            fix_lines_absent=0,
            fix_lines_total=0,
        )

    content = repo.get_file_at_version(tag, file_path)

    # File doesn't exist in this version
    if content is None:
        deleted_lines = file_patch.all_deleted_lines
        added_lines = file_patch.all_added_lines
        return FileMatchResult(
            file_path=file_path,
            found=False,
            vulnerable_lines_matched=0,
            vulnerable_lines_total=len(deleted_lines),
            fix_lines_absent=0,
            fix_lines_total=len(added_lines),
        )

    normalized_content_lines = [normalize(l) for l in content.splitlines()]
    content_set = set(normalized_content_lines)

    deleted_lines = file_patch.all_deleted_lines
    added_lines = file_patch.all_added_lines

    # Count how many vulnerable (deleted) lines appear in this version
    vuln_matched = 0
    for line in deleted_lines:
        if normalize(line) in content_set:
            vuln_matched += 1

    # Count how many fix (added) lines are absent from this version
    fix_absent = 0
    for line in added_lines:
        if normalize(line) not in content_set:
            fix_absent += 1

    return FileMatchResult(
        file_path=file_path,
        found=True,
        vulnerable_lines_matched=vuln_matched,
        vulnerable_lines_total=len(deleted_lines),
        fix_lines_absent=fix_absent,
        fix_lines_total=len(added_lines),
    )


def is_version_affected(file_results: List[FileMatchResult]) -> bool:
    """Decide if a version is affected based on file match results.

    High-recall strategy: affected if ANY file shows vulnerability indicators.
    A file indicates vulnerability if:
      - Any deleted (vulnerable) line is present, OR
      - Any added (fix) line is absent
    """
    for fr in file_results:
        if not fr.found:
            continue
        if fr.vulnerable_lines_matched > 0:
            return True
        if fr.fix_lines_absent > 0:
            return True
    return False


def match_version(
    repo: GitRepo,
    patch: PatchInfo,
    tag: str,
) -> VersionResult:
    """Check if a single version tag is affected."""
    file_results = []
    for fp in patch.file_patches:
        fr = match_file_against_version(repo, fp, tag)
        file_results.append(fr)

    affected = is_version_affected(file_results)
    return VersionResult(
        version=tag,
        is_affected=affected,
        file_results=file_results,
    )


def find_affected_versions(
    repo: GitRepo,
    patch: PatchInfo,
    tags: List[str],
) -> List[VersionResult]:
    """Check all version tags and return results."""
    results = []
    for tag in tags:
        result = match_version(repo, patch, tag)
        results.append(result)
    return results
