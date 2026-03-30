"""Experiment: run the three-layer pipeline and show version counts at each stage."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from evaluation.interface import Dataset
from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from pipeline.core import run_pipeline, PipelineResult
from tqdm import tqdm


# ---- Configuration ----
DATASET_PATH = "evaluation/benchmark/Dataset.json"
REPOS_DIR = "data/repos"
# repos=None,  # None = all repos
# repos=["FFmpeg", "ImageMagick", "curl", "httpd", "linux", "openjpeg", "openssl", "qemu", "wireshark"],
REPOS = ["curl", "openssl"]
MAX_CVES = 0  # 0 = no limit

# ---- Repo cache ----
_repo_cache: Dict[str, GitRepo] = {}


def get_repo(repo_path: str) -> GitRepo:
    if repo_path not in _repo_cache:
        _repo_cache[repo_path] = GitRepo(repo_path)
    return _repo_cache[repo_path]


def main():
    dataset = Dataset.load(DATASET_PATH)
    repos_dir = Path(REPOS_DIR)

    # Collect entries
    entries = []
    for entry in dataset:
        if REPOS and entry.repo not in REPOS:
            continue
        entries.append(entry)
        if 0 < MAX_CVES <= len(entries):
            break

    # Run pipeline per CVE
    repo_results: Dict[str, List[PipelineResult]] = defaultdict(list)

    for entry in tqdm(entries, desc="Pipeline", unit="CVE"):
        repo = get_repo(str(repos_dir / entry.repo))
        patch = parse_commits(repo, entry.all_commits)

        if not patch.file_patches:
            continue

        result = run_pipeline(repo, patch, entry.cve_id, entry.repo, entry.affected_versions)
        repo_results[entry.repo].append(result)

    # Print results
    print()
    print("=" * 110)
    print("THREE-LAYER PIPELINE EXPERIMENT")
    print("=" * 110)

    header = (f"  {'Repo':<15} {'#CVE':>5} {'Total':>8} {'PreFilt':>8} "
              f"{'Layer1':>8} {'Layer2':>8} {'States':>8} {'GT':>8} "
              f"{'L1 Cov%':>8} {'L2 Cov%':>8}")
    print(header)
    print("  " + "-" * 103)

    total_cves = 0

    for repo_name in sorted(repo_results):
        results = repo_results[repo_name]
        n = len(results)
        total_cves += n

        s = lambda attr: sum(getattr(r, attr) for r in results)

        avg_total = s('total_tags') // n
        avg_prefilt = s('after_prefilter') // n
        avg_l1 = s('after_layer1') // n
        avg_l2 = s('after_layer2') // n
        avg_states = s('unique_states') // n
        avg_gt = s('ground_truth') // n

        # Coverage: what % of GT is covered by each layer
        total_gt = s('ground_truth')
        l1_cov = s('gt_covered_by_layer1') / total_gt * 100 if total_gt > 0 else 0
        l2_cov = s('gt_covered_by_layer2') / total_gt * 100 if total_gt > 0 else 0

        print(f"  {repo_name:<15} {n:>5} {avg_total:>8} {avg_prefilt:>8} "
              f"{avg_l1:>8} {avg_l2:>8} {avg_states:>8} {avg_gt:>8} "
              f"{l1_cov:>7.1f}% {l2_cov:>7.1f}%")

    print()
    print("Columns:")
    print("  Total    = all tags in the repo")
    print("  PreFilt  = after removing non-release tags (dev/rc/beta/...)")
    print("  Layer1   = code introduction -> fix (maximum candidate range)")
    print("  Layer2   = after excluding cherry-picked fixes")
    print("  States   = unique code states (change points to check)")
    print("  GT       = ground truth affected versions")
    print("  L1 Cov%  = % of GT versions covered by Layer 1")
    print("  L2 Cov%  = % of GT versions covered by Layer 2")


if __name__ == "__main__":
    main()
