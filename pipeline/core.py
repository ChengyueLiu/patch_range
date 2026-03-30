"""Three-layer pipeline for establishing reliable candidate range.

Layer 1: Trace code introduction → fix. Maximum candidate range.
Layer 2: Exclude cherry-picked fixes.
Layer 3: Find change points (unique code states).

All layers computed in a single pass over tags for efficiency.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from typing import List, Set, Dict, Optional, Tuple

from vara.interface import PatchInfo, FilePatch
from vara.repo import GitRepo
from vara.tag_filter import filter_release_tags
from vara.patch_parser import parse_commits


def normalize(line: str) -> str:
    """Normalize a line for comparison: strip, collapse whitespace, remove spaces around operators."""
    s = line.strip()
    s = re.sub(r'\s+', ' ', s)
    # Remove spaces around common C operators
    s = re.sub(r'\s*([*/%+\-&|^=<>!,;(){}[\]])\s*', r'\1', s)
    return s


# ============================================================
# Layer 1: Trace code introduction
# ============================================================

_file_intro_cache: Dict[str, Dict[str, List[str]]] = {}  # repo_path -> {file -> [commits]}


def find_file_introductions(repo: GitRepo, file_path: str) -> List[str]:
    """Find all commits that introduced this file across all branches (cached)."""
    repo_key = str(repo.path)
    if repo_key not in _file_intro_cache:
        _file_intro_cache[repo_key] = {}
    cache = _file_intro_cache[repo_key]

    if file_path in cache:
        return cache[file_path]

    try:
        output = repo._run(
            ["log", "--all", "--diff-filter=A", "--format=%H", "--", file_path],
            check=True,
        )
        result = [c.strip() for c in output.splitlines() if c.strip()]
    except subprocess.CalledProcessError:
        result = []

    cache[file_path] = result
    return result


_trace_origin_cache: Dict[str, List[str]] = {}  # "repo:file:commit" -> results


def trace_code_origin(
    repo: GitRepo,
    file_path: str,
    file_intro_commit: str,
    search_lines: List[str],
    depth: int = 0,
    max_depth: int = 3,
) -> List[str]:
    """If code was migrated from another file, trace back to the original file.

    Checks if the code existed before the file was created by searching
    at file_intro_commit~1. If found, traces the old file's introduction.
    Returns all introduction commits found for the original file(s).
    """
    cache_key = f"{repo.path}:{file_path}:{file_intro_commit}"
    if cache_key in _trace_origin_cache:
        return _trace_origin_cache[cache_key]

    try:
        parent = repo._run(["rev-parse", file_intro_commit + "~1"], check=True).strip()
    except subprocess.CalledProcessError:
        _trace_origin_cache[cache_key] = []
        return []

    results = []
    for line in search_lines:
        stripped = line.strip()
        if not stripped or len(stripped) < 10:
            continue

        candidates = [stripped]
        tokens = re.split(r'[\s=(,;]+', stripped)
        for tok in tokens:
            if len(tok) >= 10 and not tok.startswith(('if', 'for', 'while', 'return')):
                candidates.append(tok)

        for pattern in candidates:
            try:
                r = subprocess.run(
                    ["git", "grep", "-l", "--fixed-strings", pattern, parent, "--"],
                    cwd=str(repo.path), capture_output=True, text=True,
                )
                if r.returncode == 0 and r.stdout.strip():
                    old_file = r.stdout.strip().splitlines()[0].split(":", 1)[1]
                    old_intros = find_file_introductions(repo, old_file)
                    results.extend(old_intros)
                    if old_intros and depth < max_depth:
                        deeper = trace_code_origin(
                            repo, old_file, old_intros[-1], search_lines,
                            depth=depth + 1, max_depth=max_depth,
                        )
                        results.extend(deeper)
                    _trace_origin_cache[cache_key] = results
                    return results
            except Exception:
                continue

    _trace_origin_cache[cache_key] = results
    return results


def layer1(repo: GitRepo, patch: PatchInfo, release_tags: Set[str]) -> Set[str]:
    """Layer 1: trace code introduction, get maximum candidate range.

    For each patched file:
    1. git log --follow to find file introduction (fast)
    2. Check if code existed before file creation (one git grep)
    3. If yes, trace the original file too

    Then: git tag --contains for all intro commits, minus fix tags.
    """
    intro_commits: List[str] = []

    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue

        # Step 1: file introduction (all branches)
        file_intros = find_file_introductions(repo, path)
        intro_commits.extend(file_intros)

        # Step 2+3: check for cross-file migration
        if file_intros:
            earliest_intro = file_intros[-1]  # last = earliest in git log output

            # Try deleted lines first, fall back to context lines
            old_intros = []
            if fp.all_deleted_lines:
                old_intros = trace_code_origin(repo, path, earliest_intro, fp.all_deleted_lines)
            if not old_intros:
                context_lines = [l for hunk in fp.hunks for l in hunk.context_lines]
                if context_lines:
                    old_intros = trace_code_origin(repo, path, earliest_intro, context_lines)

            intro_commits.extend(old_intros)

    if not intro_commits:
        return set()

    # Union of all tags containing any introduction commit (widest range)
    candidates: Set[str] = set()
    for intro in set(intro_commits):
        candidates.update(repo.tags_containing(intro))

    # Subtract tags containing ALL fixing commits (not any)
    # A version is only fixed if it has ALL the fixes
    if patch.commit_hashes:
        fix_tag_sets = [repo.tags_containing(fc) for fc in patch.commit_hashes]
        fully_fixed = fix_tag_sets[0]
        for fts in fix_tag_sets[1:]:
            fully_fixed = fully_fixed & fts  # intersection: must have ALL fixes
        candidates -= fully_fixed

    return candidates & release_tags


# ============================================================
# Layer 2 + 3: Single pass analysis per tag
# ============================================================

@dataclass
class TagAnalysis:
    """Analysis result for a single tag."""
    tag: str
    fix_fully_applied: bool = False
    code_hash: str = ""


def analyze_tag_from_cache(
    patch: PatchInfo,
    tag: str,
    file_paths: List[str],
    batch_results: Dict[tuple, Optional[str]],
) -> TagAnalysis:
    """Analyze a single tag using pre-fetched file contents."""
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
        content_set = set(normalize(l) for l in content.splitlines())

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
    """Analyze a single tag for Layer 2 and 3."""
    result = TagAnalysis(tag=tag)
    hasher = hashlib.md5()

    all_vuln_absent = True
    all_fix_present = True
    any_file_found = False

    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if path is None:
            continue

        content = repo.find_file_at_version(tag, path)

        if content is None:
            hasher.update(b"__FILE_NOT_FOUND__")
            all_fix_present = False
            continue

        any_file_found = True
        hasher.update(content.encode("utf-8", errors="replace"))
        content_set = set(normalize(l) for l in content.splitlines())

        # Check deleted lines
        for line in fp.all_deleted_lines:
            if normalize(line) in content_set:
                all_vuln_absent = False
                break

        # Check added lines
        for line in fp.all_added_lines:
            if normalize(line) not in content_set:
                all_fix_present = False
                break

    result.fix_fully_applied = any_file_found and all_vuln_absent and all_fix_present
    result.code_hash = hasher.hexdigest()
    return result


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
    gt_covered_by_layer1: int = 0
    gt_covered_by_layer2: int = 0


def run_pipeline(
    repo: GitRepo,
    patch: PatchInfo,
    cve_id: str,
    repo_name: str,
    gt_versions: List[str],
) -> PipelineResult:
    """Run the three-layer pipeline."""
    result = PipelineResult(cve_id=cve_id, repo=repo_name)

    all_tags = repo.get_all_tags()
    result.total_tags = len(all_tags)

    release_tags = filter_release_tags(all_tags)
    release_set = set(release_tags)
    result.after_prefilter = len(release_tags)

    # Layer 1: tracing
    l1 = layer1(repo, patch, release_set)
    result.after_layer1 = len(l1)

    # Layer 2 + 3: batch read all files, then analyze
    l2_candidates: Set[str] = set()
    state_map: Dict[str, List[str]] = {}

    # Collect all (tag, file) pairs we need to read
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    batch_requests = [(tag, path) for tag in l1 for path in file_paths]

    # Batch read all files in one git process
    batch_results = repo.batch_get_files(batch_requests)

    for tag in l1:
        analysis = analyze_tag_from_cache(patch, tag, file_paths, batch_results)

        if not analysis.fix_fully_applied:
            l2_candidates.add(tag)

            h = analysis.code_hash
            if h not in state_map:
                state_map[h] = []
            state_map[h].append(tag)

    result.after_layer2 = len(l2_candidates)
    result.unique_states = len(state_map)

    gt_set = set(gt_versions)
    result.ground_truth = len(gt_set)
    result.gt_covered_by_layer1 = len(gt_set & l1)
    result.gt_covered_by_layer2 = len(gt_set & l2_candidates)

    return result
