"""Experiment: run the three-layer pipeline and show version counts at each stage."""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

from evaluation.interface import Dataset, CVEEntry
from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from pipeline.core import run_pipeline, PipelineResult
from tqdm import tqdm


# ---- Configuration ----
DATASET_PATH = "evaluation/benchmark/Dataset_amended.json"
REPOS_DIR = "data/repos"
# repos=None,  # None = all repos
# repos=["FFmpeg", "ImageMagick", "curl", "httpd", "linux", "openjpeg", "openssl", "qemu", "wireshark"],
REPOS = ["FFmpeg", "ImageMagick", "curl", "httpd", "openjpeg", "openssl", "qemu", "wireshark"]
MAX_CVES = 0  # 0 = no limit, per repo
NUM_WORKERS = 12  # parallel workers, 1 = sequential


def _run_single(args: Tuple) -> PipelineResult:
    """Worker function for parallel execution."""
    repos_dir, cve_id, repo_name, all_commits, affected_versions = args
    repo = GitRepo(str(Path(repos_dir) / repo_name))
    patch = parse_commits(repo, all_commits)
    if not patch.file_patches:
        return None
    result = run_pipeline(repo, patch, cve_id, repo_name, affected_versions)
    repo.flush_cache()
    return result


def main():
    dataset = Dataset.load(DATASET_PATH)

    # Collect entries (max per repo)
    entries = []
    repo_count = defaultdict(int)
    for entry in dataset:
        if REPOS and entry.repo not in REPOS:
            continue
        if MAX_CVES > 0 and repo_count[entry.repo] >= MAX_CVES:
            continue
        entries.append(entry)
        repo_count[entry.repo] += 1

    # Build worker args
    worker_args = [
        (REPOS_DIR, e.cve_id, e.repo, e.all_commits, e.affected_versions)
        for e in entries
    ]

    # Run pipeline
    repo_results: Dict[str, List[PipelineResult]] = defaultdict(list)

    if NUM_WORKERS <= 1:
        for args in tqdm(worker_args, desc="Pipeline", unit="CVE"):
            result = _run_single(args)
            if result:
                repo_results[result.repo].append(result)
    else:
        with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            futures = {executor.submit(_run_single, args): args for args in worker_args}
            for future in tqdm(as_completed(futures), total=len(futures), desc="Pipeline", unit="CVE"):
                result = future.result()
                if result:
                    repo_results[result.repo].append(result)

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
