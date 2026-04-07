"""Classify whether a version is vulnerable based on context-aware deleted lines matching.

Key insight: deleted lines must appear near the SAME CODE LOCATION as in the patch,
not just anywhere in the file. We use hunk context lines to locate the right region,
then check if deleted lines exist within that region.

This addresses the main FP cause: same line appearing in different parts of the file.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple, Dict

from vara.interface import PatchInfo, FilePatch, HunkChange
from pipeline.line_filter import is_meaningful_line


def normalize(line: str) -> str:
    """Normalize a line for comparison."""
    s = line.strip()
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'\s*([*/%+\-&|^=<>!,;(){}[\]])\s*', r'\1', s)
    return s


def _find_context_position(content_lines: List[str], context_lines: List[str]) -> Optional[int]:
    """Find where hunk context lines appear in the file content.

    Returns the line index of the best context match, or None.
    Requires at least 2 consecutive context lines to match.
    """
    if not context_lines:
        return None

    norm_content = [normalize(l) for l in content_lines]
    norm_ctx = [normalize(l) for l in context_lines if normalize(l)]

    if len(norm_ctx) < 2:
        return None

    target = norm_ctx[0]
    best_idx = None
    best_score = 0

    for i, line in enumerate(norm_content):
        if line == target:
            score = 1
            for j, ctx in enumerate(norm_ctx[1:], 1):
                if i + j < len(norm_content) and norm_content[i + j] == ctx:
                    score += 1
                else:
                    break
            if score > best_score:
                best_score = score
                best_idx = i

    # Require at least 2 context lines to match consecutively
    if best_score >= 2:
        return best_idx
    return None


def classify_file_version(
    content: str,
    file_patch: FilePatch,
    region_size: int = 50,
) -> Tuple[str, int, int]:
    """Classify a version for one file using context-aware matching.

    Returns:
        (classification, matched_in_region, total_meaningful)
        classification: "VULN" | "UNCLEAR"
    """
    meaningful_del = [l for l in file_patch.all_deleted_lines if is_meaningful_line(l)]
    if not meaningful_del:
        return "UNCLEAR", 0, 0

    content_lines = content.splitlines()
    norm_content = [normalize(l) for l in content_lines]

    total_matched_in_region = 0
    total_hunks_with_context = 0
    total_hunks_matched = 0

    for hunk in file_patch.hunks:
        hunk_meaningful_del = [l for l in hunk.deleted_lines if is_meaningful_line(l)]
        if not hunk_meaningful_del:
            continue

        # Step 1: locate the code region via context lines
        ctx_pos = _find_context_position(content_lines, hunk.context_lines)

        if ctx_pos is not None:
            total_hunks_with_context += 1
            # Step 2: check deleted lines within the region
            region_start = max(0, ctx_pos - region_size)
            region_end = min(len(content_lines), ctx_pos + region_size)
            region_set = set(normalize(l) for l in content_lines[region_start:region_end])

            matched = sum(1 for l in hunk_meaningful_del if normalize(l) in region_set)
            total_matched_in_region += matched

            if matched > 0:
                total_hunks_matched += 1
        else:
            # Context not found: can't locate the region
            # Fall back to global check but require ALL meaningful lines to match
            content_set = set(norm_content)
            matched = sum(1 for l in hunk_meaningful_del if normalize(l) in content_set)
            if matched == len(hunk_meaningful_del) and len(hunk_meaningful_del) >= 2:
                total_matched_in_region += matched
                total_hunks_matched += 1

    if total_matched_in_region > 0 and total_hunks_matched > 0:
        return "VULN", total_matched_in_region, len(meaningful_del)

    return "UNCLEAR", 0, len(meaningful_del)


def classify_version(
    file_contents: Dict[str, Optional[str]],
    patch: PatchInfo,
) -> Tuple[str, int]:
    """Classify a version across all patched files.

    Returns (classification, total_matched).
    VULN if ANY file shows reliable context-aware vulnerability indicators.
    """
    total_matched = 0
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if not path:
            continue
        content = file_contents.get(path)
        if content is None:
            continue
        classification, matched, _ = classify_file_version(content, fp)
        total_matched += matched
        if classification == "VULN":
            return "VULN", total_matched

    return "UNCLEAR", total_matched
