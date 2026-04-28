"""Compute precision/recall/F1 for a run, compared to ground truth.

Reads results.jsonl from a data/runs/<name>/ directory and the GT from
benchmark/Dataset_amended.json, then prints tag-level metrics per repo
and aggregate.

Two stages can be reported (set STAGE in main()):
  - "layer1"     — predict every Layer-1 candidate as VULN (high-recall ceiling)
  - "classifier" — use our_earliest from the deterministic classifier (current default)
  - "both"       — print both, side by side

Edit the config block in main() to point at a run directory and choose stages.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1

DATASET_PATH = "benchmark/Dataset_amended.json"
RUNS_DIR = "data/runs"


# ---------------------------------------------------------------------------
# Per-CVE metrics
# ---------------------------------------------------------------------------

def _classify_case(our_set, gt_in, tag_order):
    """Re-derive case label (EXACT/SAFE/EARLY/NO_VULN/NO_GT) from a predicted set.

    This is per-stage: the case depends on what tags the stage predicted as VULN.
    """
    if not our_set:
        return "NO_VULN", None
    if not gt_in:
        return "NO_GT", None
    pred_e = min(our_set, key=lambda t: tag_order.get(t, 10**9))
    gt_e = min(gt_in, key=lambda t: tag_order.get(t, 10**9))
    dist = tag_order.get(pred_e, 10**9) - tag_order.get(gt_e, 10**9)
    if dist == 0:
        return "EXACT", 0
    return ("SAFE", dist) if dist > 0 else ("EARLY", dist)


def _per_cve_metrics(args):
    rec, dataset, stage = args
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

        if stage == "layer1":
            # All Layer-1 candidates predicted as VULN — the high-recall ceiling.
            our_set = set(candidates)
        elif stage == "classifier":
            our_e = rec.get("our_earliest")
            if our_e and our_e != "-":
                our_idx = tag_order.get(our_e, 10**9)
                our_set = {t for t in candidates if tag_order.get(t, 10**9) >= our_idx}
            else:
                our_set = set()
        else:
            raise ValueError(f"Unknown stage: {stage}")

        case, dist = _classify_case(our_set, gt, tag_order)
        tp = len(our_set & gt)
        fp = len(our_set - gt)
        fn = len(gt - our_set)
        return (cve, entry["repo"], case, dist, tp, fp, fn)
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

def cmd_report(run_dir: Path, stage: str, show_errors: bool, workers: int):
    print(f"\nRun: {run_dir}   Stage: {stage}")
    results = _load_results(run_dir)
    dataset = json.load(open(DATASET_PATH))

    per_cve = []
    args_list = [(r, dataset, stage) for r in results]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_per_cve_metrics, a) for a in args_list]
        for fut in tqdm(as_completed(futures), total=len(futures), desc=f"metrics[{stage}]"):
            r = fut.result()
            if r:
                per_cve.append(r)

    metrics = _print_metrics(per_cve, title=f"Tag-level metrics — stage={stage}")
    _print_case_distribution(per_cve)
    if show_errors:
        _print_errors(per_cve)

    out_path = run_dir / f"metrics_{stage}.json"
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved: {out_path}")


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
    # ============================================================
    # Edit this block to control what gets reported.
    # ============================================================
    RUN_DIR = "latest"          # "latest" -> most recent run, or e.g. "data/runs/program_..."
    STAGE = "both"              # "layer1" | "classifier" | "both"
    SHOW_ERRORS = False         # show top-N EARLY/SAFE example tables
    WORKERS = 8
    # For comparison mode (compares two runs' classifier output), set both:
    COMPARE_A = None            # e.g. "data/runs/run_a"
    COMPARE_B = None            # e.g. "data/runs/run_b"
    # ============================================================

    if COMPARE_A and COMPARE_B:
        cmd_compare(Path(COMPARE_A), Path(COMPARE_B))
        return

    run_dir = _latest_run() if RUN_DIR == "latest" else Path(RUN_DIR)

    stages = ["layer1", "classifier"] if STAGE == "both" else [STAGE]
    for stage in stages:
        cmd_report(run_dir, stage=stage, show_errors=SHOW_ERRORS, workers=WORKERS)


if __name__ == "__main__":
    main()
