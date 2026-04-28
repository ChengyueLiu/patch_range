"""Pipeline orchestrator: run all phases on a single CVE and report stats.

`run_pipeline()` is what the entry scripts call. It chains:
  Phase 1 (candidate range)
    → Layer 2/3 analysis (cherry-pick exclusion + state dedup)

Layer 2 and Layer 3 work off the same per-tag analysis: both want to
inspect each tag's content for the patched files. We bundle them in
`analyze_tag_from_cache()` so the heavy git reads happen only once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from app.git_lib.interface import PatchInfo
from app.git_lib.repo import GitRepo
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1
from app.utils import normalize


# ---------------------------------------------------------------------------
# Per-tag analysis (Layer 2: cherry-pick exclusion, Layer 3: state dedup)
# ---------------------------------------------------------------------------

@dataclass
class TagAnalysis:
    tag: str
    fix_fully_applied: bool = False
    code_hash: str = ""


def analyze_tag_from_cache(
    patch: PatchInfo,
    tag: str,
    file_paths: List[str],
    batch_results: Dict[tuple, Optional[str]],
) -> TagAnalysis:
    """Detect (a) whether the fix is fully applied at this tag and
    (b) compute a hash of the patched files' content for state dedup."""
    result = TagAnalysis(tag=tag)
    hasher = hashlib.md5()

    all_vuln_absent = True
    all_fix_present = True
    any_file_found = False

    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue

        content = batch_results.get((tag, path))
        if content is None:
            hasher.update(b"__FILE_NOT_FOUND__")
            all_fix_present = False
            continue

        any_file_found = True
        hasher.update(content.encode("utf-8", errors="replace"))
        content_set = {normalize(l) for l in content.splitlines()}

        for line in fp.all_deleted_lines:
            if normalize(line) in content_set:
                all_vuln_absent = False
                break
        for line in fp.all_added_lines:
            if normalize(line) not in content_set:
                all_fix_present = False
                break

    result.fix_fully_applied = any_file_found and all_vuln_absent and all_fix_present
    result.code_hash = hasher.hexdigest()
    return result


def analyze_tag(repo: GitRepo, patch: PatchInfo, tag: str) -> TagAnalysis:
    """Like analyze_tag_from_cache but reads from disk (no batch cache)."""
    file_paths = [fp.old_path or fp.new_path
                  for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    batch = {(tag, p): repo.find_file_at_version(tag, p) for p in file_paths}
    return analyze_tag_from_cache(patch, tag, file_paths, batch)


# ---------------------------------------------------------------------------
# Top-level pipeline runner
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    """Per-CVE pipeline statistics."""
    cve_id: str = ""
    repo: str = ""
    total_tags: int = 0
    after_prefilter: int = 0
    after_layer1: int = 0
    after_layer2: int = 0
    unique_states: int = 0
    ground_truth: int = 0
    gt_covered_by_layer1: int = 0
    gt_covered_by_layer2: int = 0


def run_pipeline(
    repo: GitRepo,
    patch: PatchInfo,
    cve_id: str,
    repo_name: str,
    gt_versions: List[str],
) -> PipelineResult:
    """Run Phase 1 + Layer 2/3 analysis on one CVE, return stats."""
    result = PipelineResult(cve_id=cve_id, repo=repo_name)

    all_tags = repo.get_all_tags()
    result.total_tags = len(all_tags)

    release_tags = filter_release_tags(all_tags)
    release_set = set(release_tags)
    result.after_prefilter = len(release_tags)

    l1 = layer1(repo, patch, release_set)
    result.after_layer1 = len(l1)

    l2_candidates: Set[str] = set()
    state_map: Dict[str, List[str]] = {}

    file_paths = [fp.old_path or fp.new_path
                  for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    batch_requests = [(tag, path) for tag in l1 for path in file_paths]
    batch_results = repo.batch_get_files(batch_requests)

    for tag in l1:
        analysis = analyze_tag_from_cache(patch, tag, file_paths, batch_results)
        if not analysis.fix_fully_applied:
            l2_candidates.add(tag)
            state_map.setdefault(analysis.code_hash, []).append(tag)

    result.after_layer2 = len(l2_candidates)
    result.unique_states = len(state_map)

    gt_set = set(gt_versions)
    result.ground_truth = len(gt_set)
    result.gt_covered_by_layer1 = len(gt_set & l1)
    result.gt_covered_by_layer2 = len(gt_set & l2_candidates)

    return result
