"""State deduplication: group candidate-range tags by code hash.

Layer 3 already computes a code hash per tag (MD5 of patched-file contents).
Tags with the same hash have identical vulnerability status, so the LLM only
needs to judge one representative tag per unique state.

Usage:
    from app.phase2.state_dedup import build_unique_states

    states = build_unique_states(repo, patch, candidate_tags, tag_order)
    for s in states:
        # s.representative_tag — earliest tag in this state
        # s.tags — all tags with this code hash
        verdict = judge(s.representative_tag)
        # apply verdict to all s.tags
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from app.git_lib.interface import PatchInfo
from app.git_lib.repo import GitRepo
from app.utils import normalize


@dataclass
class UniqueState:
    """A group of tags that share the same code content for all patched files."""
    code_hash: str
    representative_tag: str   # earliest tag by tag_order
    tags: List[str]           # all tags in chronological order
    file_contents: Dict[str, Optional[str]] = field(default_factory=dict)
    # classification from program-based matcher (set externally)
    program_verdict: str = ""  # "VULN" | "UNCLEAR"


def _code_hash(
    file_paths: List[str],
    batch: Dict[tuple, Optional[str]],
    tag: str,
) -> str:
    """Compute the code hash for a tag — same logic as Layer 3."""
    h = hashlib.md5()
    for path in file_paths:
        content = batch.get((tag, path))
        if content is None:
            h.update(b"__FILE_NOT_FOUND__")
        else:
            h.update(content.encode("utf-8", errors="replace"))
    return h.hexdigest()


def build_unique_states(
    repo: GitRepo,
    patch: PatchInfo,
    candidate_tags: Set[str],
    tag_order: Dict[str, int],
) -> List[UniqueState]:
    """Group candidate tags by code hash and return unique states.

    Returns:
        List of UniqueState, sorted chronologically by representative tag
        (earliest first).
    """
    file_paths = [
        fp.old_path or fp.new_path
        for fp in patch.file_patches
        if (fp.old_path or fp.new_path)
    ]
    if not file_paths:
        return []

    sorted_tags = sorted(candidate_tags, key=lambda t: tag_order.get(t, 10**9))

    # Batch-read all files in one git process
    batch = repo.batch_get_files([(t, p) for t in sorted_tags for p in file_paths])

    # Group by hash
    hash_to_state: Dict[str, UniqueState] = {}
    for tag in sorted_tags:
        h = _code_hash(file_paths, batch, tag)
        if h not in hash_to_state:
            # Build file_contents dict for the representative tag
            fc = {p: batch.get((tag, p)) for p in file_paths}
            hash_to_state[h] = UniqueState(
                code_hash=h,
                representative_tag=tag,
                tags=[tag],
                file_contents=fc,
            )
        else:
            hash_to_state[h].tags.append(tag)

    # Sort states by their earliest tag
    states = sorted(
        hash_to_state.values(),
        key=lambda s: tag_order.get(s.representative_tag, 10**9),
    )
    return states
