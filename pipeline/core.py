"""Three-layer pipeline for establishing reliable candidate range.

Layer 1: Code introduction → fix. Maximum candidate range.
Layer 2: Exclude cherry-picked fixes.
Layer 3: Find change points (versions where code actually changed).

Independent from vara/ - does not modify existing code.
Reuses vara.repo and vara.patch_parser for git operations and diff parsing.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional

from vara.interface import PatchInfo, FilePatch
from vara.repo import GitRepo
from vara.tag_filter import filter_release_tags
from vara.patch_parser import parse_commits


def normalize(line: str) -> str:
    """Normalize a line for comparison."""
    import re
    return re.sub(r'\s+', ' ', line.strip())


# ============================================================
# Layer 1: Code introduction → fix
# ============================================================

def find_file_introduction(repo: GitRepo, file_path: str) -> Optional[str]:
    """Find the earliest commit that introduced this file (tracks renames)."""
    try:
        output = repo._run(
            ["log", "--follow", "--diff-filter=A", "--format=%H", "--", file_path],
            check=True,
        )
        commits = [c.strip() for c in output.splitlines() if c.strip()]
        if commits:
            return commits[-1]  # last = earliest (git log is reverse chronological)
    except subprocess.CalledProcessError:
        pass
    return None


def layer1(repo: GitRepo, patch: PatchInfo, release_tags: Set[str]) -> Set[str]:
    """Layer 1: all versions between code introduction and fix."""
    # Find earliest code introduction across all patched files
    intro_commits = []
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue
        intro = find_file_introduction(repo, path)
        if intro:
            intro_commits.append(intro)

    if not intro_commits:
        return set()

    # Union of all tags containing any introduction commit (widest range)
    candidates: Set[str] = set()
    for intro in intro_commits:
        candidates.update(repo.tags_containing(intro))

    # Subtract tags containing any fixing commit
    for fix_commit in patch.commit_hashes:
        candidates -= repo.tags_containing(fix_commit)

    return candidates & release_tags


# ============================================================
# Layer 2: Exclude cherry-picked fixes
# ============================================================

def is_fix_present(repo: GitRepo, patch: PatchInfo, tag: str) -> bool:
    """Check if the fix is fully applied in a version."""
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue

        content = repo.find_file_at_version(tag, path)
        if content is None:
            return False

        content_set = set(normalize(l) for l in content.splitlines())

        for line in fp.all_deleted_lines:
            if normalize(line) in content_set:
                return False  # vulnerable code still present

        for line in fp.all_added_lines:
            if normalize(line) not in content_set:
                return False  # fix not fully applied

    return True


def layer2(repo: GitRepo, patch: PatchInfo, candidates: Set[str]) -> Set[str]:
    """Layer 2: exclude versions where fix was cherry-picked."""
    return {tag for tag in candidates if not is_fix_present(repo, patch, tag)}


# ============================================================
# Layer 3: Find change points
# ============================================================

def compute_code_hash(repo: GitRepo, patch: PatchInfo, tag: str) -> str:
    """Compute a hash representing the state of patched files at a version."""
    hasher = hashlib.md5()
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue
        content = repo.find_file_at_version(tag, path)
        if content is None:
            hasher.update(b"__FILE_NOT_FOUND__")
        else:
            hasher.update(content.encode("utf-8", errors="replace"))
    return hasher.hexdigest()


def layer3(repo: GitRepo, patch: PatchInfo, candidates: Set[str]) -> tuple:
    """Layer 3: find unique code states among candidates.

    Returns:
        (all_candidates, unique_state_count, state_groups)
        - all_candidates: same as input (no versions excluded)
        - unique_state_count: number of distinct code states
        - state_groups: dict of hash -> list of tags
    """
    state_map: Dict[str, List[str]] = {}
    for tag in candidates:
        h = compute_code_hash(repo, patch, tag)
        if h not in state_map:
            state_map[h] = []
        state_map[h].append(tag)

    return candidates, len(state_map), state_map


# ============================================================
# Pipeline result and runner
# ============================================================

@dataclass
class PipelineResult:
    """Statistics from running the three-layer pipeline on a single CVE."""
    cve_id: str = ""
    repo: str = ""
    total_tags: int = 0
    after_prefilter: int = 0
    after_layer1: int = 0
    after_layer2: int = 0
    unique_states: int = 0
    ground_truth: int = 0
    # Coverage check: are all GT versions in layer1/layer2 candidates?
    gt_covered_by_layer1: int = 0
    gt_covered_by_layer2: int = 0


def run_pipeline(
    repo: GitRepo,
    patch: PatchInfo,
    cve_id: str,
    repo_name: str,
    gt_versions: List[str],
) -> PipelineResult:
    """Run the three-layer pipeline and collect statistics."""
    result = PipelineResult(cve_id=cve_id, repo=repo_name)

    all_tags = repo.get_all_tags()
    result.total_tags = len(all_tags)

    release_tags = filter_release_tags(all_tags)
    release_set = set(release_tags)
    result.after_prefilter = len(release_tags)

    l1 = layer1(repo, patch, release_set)
    result.after_layer1 = len(l1)

    l2 = layer2(repo, patch, l1)
    result.after_layer2 = len(l2)

    _, unique_states, _ = layer3(repo, patch, l2)
    result.unique_states = unique_states

    gt_set = set(gt_versions)
    result.ground_truth = len(gt_set)
    result.gt_covered_by_layer1 = len(gt_set & l1)
    result.gt_covered_by_layer2 = len(gt_set & l2)

    return result
