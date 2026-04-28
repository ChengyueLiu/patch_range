"""Compute precision/recall/F1 for a run, compared to ground truth.

Reads results.jsonl from a data/runs/<name>/ directory and the GT from
benchmark/Dataset_amended.json, then prints tag-level metrics per repo
and aggregate.

Usage:
    python report.py data/runs/program_v1               # F1 of one run
    python report.py --latest                            # latest run
    python report.py data/runs/v1 --show errors          # list EARLY/SAFE
    python report.py --compare data/runs/a data/runs/b   # diff two runs
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Optional, Tuple

from tqdm import tqdm

from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1

DATASET_PATH = "benchmark/Dataset_amended.json"
RUNS_DIR = "data/runs"


# ---------------------------------------------------------------------------
# Tag-set reconstruction (per-CVE)
# ---------------------------------------------------------------------------

def _our_set_from_record(rec, dataset, candidates_cache, tag_order_cache) -> set:
    """Reconstruct the set of tags we predicted as VULN for this CVE.

    Logic: take all candidate tags whose chronological order is >= our_earliest.
    NO_VULN/NO_GT records contribute an empty set.
    """
    cve = rec["cve"]
    our_e = rec.get("our_earliest")
    if not our_e:
        return set()

    repo_name = rec["repo"]
    if repo_name not in tag_order_cache:
        repo = GitRepo(f"data/repos/{repo_name}")
        tags = filter_release_tags(repo.get_all_tags())
        tag_order_cache[repo_name] = {t: i for i, t in enumerate(tags)}

    if cve not in candidates_cache:
        entry = dataset[cve]
        repo = GitRepo(f"data/repos/{repo_name}")
        commits = [c for g in entry["fixing_commits"] for c in g]
        patch = parse_commits(repo, commits)
        release_set = set(filter_release_tags(repo.get_all_tags()))
        candidates_cache[cve] = layer1(repo, patch, release_set)

    candidates = candidates_cache[cve]
    tag_order = tag_order_cache[repo_name]
    our_idx = tag_order.get(our_e, 10**9)
    return {t for t in candidates if tag_order.get(t, 10**9) >= our_idx}


def _per_cve_metrics(args):
    rec, dataset = args
    cve = rec["cve"]
    if cve not in dataset:
        return None
    entry = dataset[cve]
    try:
        repo = GitRepo(f"data/repos/{entry['repo']}")
        release_set = set(filter_release_tags(repo.get_all_tags()))
        commits = [c for g in entry["fixing_commits"] for c in g]
        patch = parse_commits(repo, commits)
        if not patch.file_patches:
            return None
        candidates = layer1(repo, patch, release_set)
        tag_order = {t: i for i, t in enumerate(filter_release_tags(repo.get_all_tags()))}

        gt = set(entry.get("affected_version", [])) & release_set
        if not gt:
            return None

        our_e = rec.get("our_earliest")
        if our_e and our_e != "-":
            our_idx = tag_order.get(our_e, 10**9)
            our_set = {t for t in candidates if tag_order.get(t, 10**9) >= our_idx}
        else:
            our_set = set()

        tp = len(our_set & gt)
        fp = len(our_set - gt)
        fn = len(gt - our_set)
        return (cve, entry["repo"], rec.get("case", "?"), rec.get("dist", None), tp, fp, fn)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_metrics(per_cve, title=""):
    repo_stats = defaultdict(lambda: [0, 0, 0])
    for cve, repo, case, dist, tp, fp, fn in per_cve:
        s = repo_stats[repo]
        s[0] += tp
        s[1] += fp
        s[2] += fn

    if title:
        print(f"\n=== {title} ===")
    print(f"{'Repo':<12} {'TP':>7} {'FP':>7} {'FN':>7} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    print("-" * 56)
    tot_tp = tot_fp = tot_fn = 0
    for r in sorted(repo_stats):
        tp, fp, fn = repo_stats[r]
        p = tp / (tp + fp) if tp + fp else 0
        rc = tp / (tp + fn) if tp + fn else 0
        f = 2 * p * rc / (p + rc) if p + rc else 0
        print(f"{r:<12} {tp:>7} {fp:>7} {fn:>7} {p:>6.3f} {rc:>6.3f} {f:>6.3f}")
        tot_tp += tp
        tot_fp += fp
        tot_fn += fn
    print("-" * 56)
    p = tot_tp / (tot_tp + tot_fp) if tot_tp + tot_fp else 0
    rc = tot_tp / (tot_tp + tot_fn) if tot_tp + tot_fn else 0
    f = 2 * p * rc / (p + rc) if p + rc else 0
    print(f"{'TOTAL':<12} {tot_tp:>7} {tot_fp:>7} {tot_fn:>7} {p:>6.3f} {rc:>6.3f} {f:>6.3f}")
    return {"precision": p, "recall": rc, "f1": f, "tp": tot_tp, "fp": tot_fp, "fn": tot_fn}


def _print_case_distribution(per_cve):
    case_counts = defaultdict(int)
    for _, _, case, _, _, _, _ in per_cve:
        case_counts[case] += 1
    measured = case_counts["EXACT"] + case_counts["SAFE"] + case_counts["EARLY"]
    print(f"\nCase distribution ({len(per_cve)} CVEs):")
    for c in ["EXACT", "SAFE", "EARLY", "NO_VULN", "NO_GT"]:
        n = case_counts.get(c, 0)
        if n:
            pct = f" ({n/measured*100:.1f}%)" if measured and c in {"EXACT", "SAFE", "EARLY"} else ""
            print(f"  {c:<10} {n}{pct}")
    if measured:
        print(f"  EXACT+SAFE: {(case_counts['EXACT']+case_counts['SAFE'])/measured*100:.1f}%")


def _print_errors(per_cve, max_per_class=20):
    early = [r for r in per_cve if r[2] == "EARLY"]
    safe = [r for r in per_cve if r[2] == "SAFE"]
    early.sort(key=lambda r: r[3] if r[3] is not None else 0)
    safe.sort(key=lambda r: -(r[3] or 0))
    print(f"\n=== EARLY ({len(early)}, sorted by most-negative dist) ===")
    print(f"{'CVE':<22} {'Repo':<12} {'Dist':>5} {'TP':>5} {'FP':>5}")
    for r in early[:max_per_class]:
        print(f"{r[0]:<22} {r[1]:<12} {str(r[3]):>5} {r[4]:>5} {r[5]:>5}")
    print(f"\n=== SAFE ({len(safe)}, sorted by largest dist) ===")
    print(f"{'CVE':<22} {'Repo':<12} {'Dist':>5} {'TP':>5} {'FN':>5}")
    for r in safe[:max_per_class]:
        print(f"{r[0]:<22} {r[1]:<12} {str(r[3]):>5} {r[4]:>5} {r[6]:>5}")


def _load_results(run_dir: Path):
    p = run_dir / "results.jsonl"
    if not p.exists():
        sys.exit(f"No results.jsonl in {run_dir}")
    return [json.loads(l) for l in open(p) if l.strip()]


def _latest_run() -> Path:
    runs = sorted(Path(RUNS_DIR).glob("*"))
    if not runs:
        sys.exit(f"No runs found in {RUNS_DIR}/")
    return runs[-1]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_report(run_dir: Path, show_errors: bool, workers: int):
    print(f"Run: {run_dir}")
    results = _load_results(run_dir)
    dataset = json.load(open(DATASET_PATH))

    per_cve = []
    args_list = [(r, dataset) for r in results]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_per_cve_metrics, a) for a in args_list]
        for fut in tqdm(as_completed(futures), total=len(futures), desc="metrics"):
            r = fut.result()
            if r:
                per_cve.append(r)

    metrics = _print_metrics(per_cve, title="Tag-level metrics")
    _print_case_distribution(per_cve)
    if show_errors:
        _print_errors(per_cve)

    # Persist metrics.json
    with open(run_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved: {run_dir / 'metrics.json'}")


def cmd_compare(run_a: Path, run_b: Path):
    print(f"A = {run_a}\nB = {run_b}\n")
    a_results = {r["cve"]: r for r in _load_results(run_a)}
    b_results = {r["cve"]: r for r in _load_results(run_b)}
    common = set(a_results) & set(b_results)
    diffs = []
    for cve in common:
        a, b = a_results[cve], b_results[cve]
        if a.get("case") != b.get("case") or a.get("our_earliest") != b.get("our_earliest"):
            diffs.append((cve, a, b))
    print(f"{len(diffs)} / {len(common)} CVEs differ")
    print(f"{'CVE':<22} {'A.case':<10} {'A.our':<22} {'B.case':<10} {'B.our':<22}")
    for cve, a, b in diffs[:50]:
        print(f"{cve:<22} {a.get('case','?'):<10} {str(a.get('our_earliest','-')):<22} "
              f"{b.get('case','?'):<10} {str(b.get('our_earliest','-')):<22}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", nargs="?", help="Run directory under data/runs/")
    ap.add_argument("--latest", action="store_true", help="Use the latest run")
    ap.add_argument("--show", default="", help="Show extra info: 'errors'")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"), help="Compare two run dirs")
    args = ap.parse_args()

    if args.compare:
        cmd_compare(Path(args.compare[0]), Path(args.compare[1]))
        return

    if args.latest:
        run_dir = _latest_run()
    elif args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        ap.print_help()
        sys.exit(1)

    cmd_report(run_dir, show_errors=("error" in args.show), workers=args.workers)


if __name__ == "__main__":
    main()
