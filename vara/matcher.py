"""High-recall matcher: check if a version is affected by a vulnerability.

Strategy for maximum recall:
A version is considered affected if ANY of these conditions hold for ANY patched file:
  1. At least one deleted line (vulnerable code) is found in the file
  2. At least one added line (fix code) is NOT found near the expected context
  3. The patched file does not exist in this version (path changed beyond recognition)

This is intentionally loose to maximize recall. Precision will be addressed in phase 2.
"""

from __future__ import annotations

import re
from typing import List, Optional

from vara.interface import PatchInfo, FilePatch, HunkChange, VersionResult, FileMatchResult
from vara.repo import GitRepo


def normalize(line: str) -> str:
    """Normalize a line for fuzzy comparison: collapse whitespace, strip."""
    return re.sub(r'\s+', ' ', line.strip())


def _find_context_region(
    content_lines: List[str],
    context_lines: List[str],
) -> Optional[int]:
    """Find where a hunk's context lines appear in the file.

    Returns the line index where the best context match starts, or None.
    """
    if not context_lines:
        return None

    norm_content = [normalize(l) for l in content_lines]
    norm_context = [normalize(l) for l in context_lines if normalize(l)]

    if not norm_context:
        return None

    target = norm_context[0]
    best_idx = None
    best_score = 0

    for i, line in enumerate(norm_content):
        if line == target:
            score = 1
            for j, ctx in enumerate(norm_context[1:], 1):
                if i + j < len(norm_content) and norm_content[i + j] == ctx:
                    score += 1
                else:
                    break
            if score > best_score:
                best_score = score
                best_idx = i

    return best_idx


def _check_lines_in_region(
    content_lines: List[str],
    target_lines: List[str],
    region_start: int,
    region_size: int = 30,
) -> int:
    """Check how many target lines appear in a region of the file."""
    start = max(0, region_start - region_size)
    end = min(len(content_lines), region_start + region_size)
    region_set = set(normalize(l) for l in content_lines[start:end])

    found = 0
    for line in target_lines:
        if normalize(line) in region_set:
            found += 1
    return found


def match_file_against_version(
    repo: GitRepo,
    file_patch: FilePatch,
    tag: str,
) -> FileMatchResult:
    """Check if a single file in a version shows signs of the vulnerability."""
    file_path = file_patch.old_path or file_patch.new_path

    # File was newly added in the fix → not relevant for vulnerability
    if file_patch.old_path is None:
        return FileMatchResult(
            file_path=file_path,
            found=False,
            vulnerable_lines_matched=0,
            vulnerable_lines_total=0,
            fix_lines_absent=0,
            fix_lines_total=0,
        )

    content = repo.find_file_at_version(tag, file_path)
    deleted_lines = file_patch.all_deleted_lines
    added_lines = file_patch.all_added_lines

    # File doesn't exist in this version → no evidence of vulnerability
    # Tracing channel handles cases where file path changed
    if content is None:
        return FileMatchResult(
            file_path=file_path,
            found=False,
            vulnerable_lines_matched=0,
            vulnerable_lines_total=0,
            fix_lines_absent=0,
            fix_lines_total=0,
        )

    content_lines = content.splitlines()
    content_norm_set = set(normalize(l) for l in content_lines)

    # Count deleted (vulnerable) lines present anywhere in the file
    vuln_matched = 0
    for line in deleted_lines:
        if normalize(line) in content_norm_set:
            vuln_matched += 1

    # Count added (fix) lines absent using context-aware matching
    fix_absent = _count_fix_absent(content_lines, content_norm_set, file_patch.hunks)

    return FileMatchResult(
        file_path=file_path,
        found=True,
        vulnerable_lines_matched=vuln_matched,
        vulnerable_lines_total=len(deleted_lines),
        fix_lines_absent=fix_absent,
        fix_lines_total=len(added_lines),
    )


def _count_fix_absent(
    content_lines: List[str],
    content_norm_set: set,
    hunks: List[HunkChange],
) -> int:
    """Count how many added lines are absent, using context to locate the right region."""
    total_absent = 0

    for hunk in hunks:
        if not hunk.added_lines:
            continue

        region_idx = _find_context_region(content_lines, hunk.context_lines)

        if region_idx is not None:
            found_in_region = _check_lines_in_region(
                content_lines, hunk.added_lines, region_idx,
            )
            total_absent += len(hunk.added_lines) - found_in_region
        else:
            for line in hunk.added_lines:
                if normalize(line) not in content_norm_set:
                    total_absent += 1

    return total_absent


def is_version_affected(file_results: List[FileMatchResult]) -> bool:
    """Decide if a version is affected based on file match results."""
    for fr in file_results:
        if not fr.found:
            continue
        if fr.vulnerable_lines_matched > 0:
            return True
        if fr.fix_lines_absent > 0:
            return True
    return False


def is_version_patched(result: VersionResult) -> bool:
    """Check if a version is clearly already patched.

    A version is considered patched if for ALL found files:
    - No vulnerable (deleted) lines are present
    - All fix (added) lines are present
    """
    has_any_found = False
    for fr in result.file_results:
        if not fr.found:
            continue
        has_any_found = True
        if fr.vulnerable_lines_matched > 0:
            return False  # still has vulnerable code
        if fr.fix_lines_absent > 0:
            return False  # fix not fully applied
    return has_any_found  # only patched if we actually checked some files


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
