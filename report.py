"""Compute precision/recall/F1 for a run, compared to ground truth.

Reports two stages side-by-side (Layer 1 ceiling vs classifier output) plus:
  - stage-to-stage delta
  - vs previous run (auto-picked second-latest program_* dir)
  - vs study Table III best baselines
  - per-repo F1/R for both stages
  - case distribution + per-repo case top

Edit the config block in main() to point at a run directory. By default it
reports on the latest run.
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

# Study (arXiv:2509.03876v2) Table III — best individual tool per metric.
STUDY_BEST = {
    "F1":  (0.778, "VCCFinder"),
    "Acc": (0.449, "VCCFinder"),
    "R":   (0.794, "V-SZZ"),
}


# ---------------------------------------------------------------------------
# Per-CVE metric extraction
# ---------------------------------------------------------------------------

def _classify_case(our_set, gt_in, tag_order):
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


def _per_cve_dual(args):
    """Compute (cve, repo, layer1_row, classifier_row) where each row is
    (case, dist, tp, fp, fn). Returns None if the CVE should be skipped."""
    rec, dataset = args
    cve = rec["cve"]
    if cve not in dataset:
        return None
    entry = dataset[cve]
    try:
        repo = GitRepo(f"data/repos/{entry['repo']}")
        release_tags = filter_release_tags(repo.get_all_tags())
        release_set = set(release_tags)
        tag_order = {t: i for i, t in enumerate(release_tags)}
        commits = [c for g in entry["fixing_commits"] for c in g]
        patch = parse_commits(repo, commits)
        if not patch.file_patches:
            return None
        candidates = layer1(repo, patch, release_set)
        gt = set(entry.get("affected_version", [])) & release_set
        if not gt:
            return None

        def metrics_for(our_set):
            case, dist = _classify_case(our_set, gt, tag_order)
            tp = len(our_set & gt)
            fp = len(our_set - gt)
            fn = len(gt - our_set)
            return (case, dist, tp, fp, fn)

        l1_set = set(candidates)
        l1_row = metrics_for(l1_set)

        our_e = rec.get("our_earliest")
        if our_e and our_e != "-":
            our_idx = tag_order.get(our_e, 10**9)
            cls_set = {t for t in candidates if tag_order.get(t, 10**9) >= our_idx}
        else:
            cls_set = set()
        cls_row = metrics_for(cls_set)

        return (cve, entry["repo"], l1_row, cls_row)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _empty_acc():
    return {"tp": 0, "fp": 0, "fn": 0, "exact": 0, "no_miss": 0, "n": 0}


def _add(acc, tp, fp, fn):
    acc["tp"] += tp
    acc["fp"] += fp
    acc["fn"] += fn
    acc["n"] += 1
    if fp == 0 and fn == 0:
        acc["exact"] += 1
    if fn == 0:
        acc["no_miss"] += 1


def _prf(acc):
    tp, fp, fn, n = acc["tp"], acc["fp"], acc["fn"], acc["n"]
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f = 2 * p * r / (p + r) if p + r else 0
    a = acc["exact"] / n if n else 0
    nm = acc["no_miss"] / n if n else 0
    return {"F1": f, "P": p, "R": r, "Acc": a, "NMR": nm,
            "tp": tp, "fp": fp, "fn": fn, "exact": acc["exact"],
            "no_miss": acc["no_miss"], "n": n}


def _aggregate(rows_by_cve, stage_idx):
    """Build {total, repos, cases_by_repo} for one stage from per-CVE rows.

    rows_by_cve: list of (cve, repo, l1_row, cls_row)
    stage_idx: 2 for Layer 1, 3 for classifier
    """
    total = _empty_acc()
    repos = defaultdict(_empty_acc)
    case_by_repo = defaultdict(lambda: defaultdict(int))  # case -> repo -> count
    for entry in rows_by_cve:
        repo = entry[1]
        case, dist, tp, fp, fn = entry[stage_idx]
        _add(total, tp, fp, fn)
        _add(repos[repo], tp, fp, fn)
        case_by_repo[case][repo] += 1
    return {
        "total": _prf(total),
        "repos": {r: _prf(a) for r, a in repos.items()},
        "case_by_repo": {c: dict(v) for c, v in case_by_repo.items()},
    }


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def _fmt_run_header(run_dir, config):
    git = config.get("code_git_head", "?")
    n = config.get("n_targets", "?")
    nrepo = len(config.get("repos", []))
    started = config.get("started_at", "?")
    return f"{run_dir.name}  |  git={git}  |  {n} CVE × {nrepo} repo  |  {started}"


def _render(run_dir, config, layer1_agg, cls_agg, prev_summary):
    L = []
    L.append("=" * 64)
    L.append(_fmt_run_header(run_dir, config))
    L.append("=" * 64)

    # Headline
    L1 = layer1_agg["total"]
    C = cls_agg["total"]
    L.append("")
    L.append("Headline")
    L.append(f"                    F1     P      R      Acc%   NMR%")
    L.append("─" * 53)
    L.append(f"Layer1            {L1['F1']:.3f}  {L1['P']:.3f}  {L1['R']:.3f}  {L1['Acc']*100:5.1f}  {L1['NMR']*100:5.1f}")
    L.append(f"classifier        {C['F1']:.3f}  {C['P']:.3f}  {C['R']:.3f}  {C['Acc']*100:5.1f}  {C['NMR']*100:5.1f}")
    L.append(f"Δ (Cls - L1)     {C['F1']-L1['F1']:+.3f} {C['P']-L1['P']:+.3f} {C['R']-L1['R']:+.3f} {(C['Acc']-L1['Acc'])*100:+5.1f}  {(C['NMR']-L1['NMR'])*100:+5.1f}")

    # vs prev run
    L.append("")
    if prev_summary is None:
        L.append("vs prev run:       not found")
    else:
        pC = prev_summary["stages"]["classifier"]["total"]
        L.append(f"vs prev run ({prev_summary['run_name']}):")
        L.append(f"  F1 {C['F1']-pC['F1']:+.3f}  P {C['P']-pC['P']:+.3f}  R {C['R']-pC['R']:+.3f}  Acc {(C['Acc']-pC['Acc'])*100:+.1f}pp  NMR {(C['NMR']-pC['NMR'])*100:+.1f}pp")

    # vs study best
    f1_b, f1_who = STUDY_BEST["F1"]
    acc_b, acc_who = STUDY_BEST["Acc"]
    r_b, r_who = STUDY_BEST["R"]
    L.append("")
    L.append("vs study best (Table III):")
    L.append(f"  F1   = {f1_b:.3f}  ({f1_who})   gap  {C['F1']-f1_b:+.3f}")
    L.append(f"  Acc% = {acc_b*100:.1f}%  ({acc_who})   gap  {(C['Acc']-acc_b)*100:+.1f}pp")
    layer1_marker = "✅" if L1["R"] > r_b else ""
    L.append(f"  R    = {r_b:.3f}  ({r_who})       gap  {C['R']-r_b:+.3f}   (Layer1 {L1['R']-r_b:+.3f} {layer1_marker})")

    # Per-repo
    L.append("")
    L.append("")
    L.append("Per-repo (sorted by classifier F1)")
    L.append("              Layer1        classifier")
    L.append("              F1    R       F1    R     ΔR")
    L.append("─" * 42)
    cls_repos = cls_agg["repos"]
    l1_repos = layer1_agg["repos"]
    for r in sorted(cls_repos, key=lambda x: -cls_repos[x]["F1"]):
        l1m = l1_repos.get(r, _prf(_empty_acc()))
        cm = cls_repos[r]
        dr = cm["R"] - l1m["R"]
        L.append(f"{r:<12} {l1m['F1']:.3f} {l1m['R']:.3f}   {cm['F1']:.3f} {cm['R']:.3f}  {dr:+.2f}")

    # Failure modes (classifier stage)
    L.append("")
    L.append("")
    L.append("Failure modes (classifier stage)")
    cbr = cls_agg["case_by_repo"]
    case_counts = {c: sum(d.values()) for c, d in cbr.items()}
    case_str = "  ".join(f"{c} {case_counts.get(c, 0)}" for c in ["EXACT", "SAFE", "EARLY", "NO_VULN"] if case_counts.get(c, 0))
    L.append(f"Case dist:     {case_str}")
    for case_name in ["NO_VULN", "SAFE", "EARLY"]:
        items = sorted(cbr.get(case_name, {}).items(), key=lambda kv: -kv[1])
        if items:
            L.append(f"{case_name+' top:':<14} " + " / ".join(f"{r} {n}" for r, n in items))
    L.append("")
    L.append("(A1-A7 分桶等数据集标注完成后再加)")

    # Saved
    L.append("")
    L.append("")
    L.append("Saved")
    for fn in ["metrics_layer1.json", "metrics_classifier.json", "metrics_summary.json", "SUMMARY.md"]:
        L.append(f"  {run_dir / fn}")

    return "\n".join(L)


def _print_legend():
    print("\n" + "=" * 64)
    print("指标说明（参照 study arXiv:2509.03876v2 Table III）")
    print("=" * 64)
    print("""
两套指标都报，方便和 baseline 横向对比：

【Version-level（tag 粒度，micro-averaged）】
  对每个 CVE：
    TP = |我们预测的 vuln tag ∩ GT|
    FP = |我们预测 - GT|
    FN = |GT - 我们预测|
  跨所有 CVE 求和后再算：
    Precision = ΣTP / (ΣTP + ΣFP)
    Recall    = ΣTP / (ΣTP + ΣFN)
    F1        = 2PR / (P+R)

【Vulnerability-level（CVE 粒度，per-CVE binary）】
  每个 CVE 二值判断：
    Acc 通过：predicted set 严格等于 GT set（FP==0 AND FN==0）
    NM  通过：predicted set 包含全部 GT（FN==0，允许有 FP）
  最后：
    Accuracy (Acc%) = Acc 通过的 CVE 数 / 总 CVE 数
    NMR      (NMR%) = NM  通过的 CVE 数 / 总 CVE 数
  注意：Acc 比 F1 严得多，tail 多一个 FP 就 fail。

【Δ row】
  Δ (Cls - L1) = classifier - Layer1。正号 = classifier 比 Layer1 好。

【Stage 含义】
  Layer1     = 把所有 Layer 1 candidates 当 VULN（高召回上界）
  classifier = 用 our_earliest 的当前 deterministic classifier
""")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_results(run_dir: Path):
    p = run_dir / "results.jsonl"
    if not p.exists():
        sys.exit(f"No results.jsonl in {run_dir}")
    return [json.loads(l) for l in open(p) if l.strip()]


def _latest_run() -> Path:
    runs = sorted(p for p in Path(RUNS_DIR).glob("program_*") if p.is_dir())
    if not runs:
        sys.exit(f"No program_* runs found in {RUNS_DIR}/")
    return runs[-1]


def _find_prev_run(run_dir: Path) -> Path | None:
    """Find the second-latest program_* run dir (ignoring `run_dir`)."""
    runs = sorted(p for p in Path(RUNS_DIR).glob("program_*")
                  if p.is_dir() and p.resolve() != run_dir.resolve())
    return runs[-1] if runs else None


def _load_prev_summary(run_dir: Path):
    prev_dir = _find_prev_run(run_dir)
    if prev_dir is None:
        return None
    p = prev_dir / "metrics_summary.json"
    if not p.exists():
        return None
    try:
        data = json.load(open(p))
        data["run_name"] = prev_dir.name
        return data
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def cmd_report(run_dir: Path, workers: int, show_legend: bool):
    config_path = run_dir / "config.json"
    config = json.load(open(config_path)) if config_path.exists() else {}

    results = _load_results(run_dir)
    dataset = json.load(open(DATASET_PATH))

    rows = []
    args_list = [(r, dataset) for r in results]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_per_cve_dual, a) for a in args_list]
        for fut in tqdm(as_completed(futures), total=len(futures), desc="metrics", leave=False):
            r = fut.result()
            if r:
                rows.append(r)

    layer1_agg = _aggregate(rows, stage_idx=2)
    cls_agg = _aggregate(rows, stage_idx=3)
    prev_summary = _load_prev_summary(run_dir)

    text = _render(run_dir, config, layer1_agg, cls_agg, prev_summary)
    print(text)

    # Persist files
    summary = {
        "run_name": run_dir.name,
        "git": config.get("code_git_head", "?"),
        "n_records": len(rows),
        "started_at": config.get("started_at"),
        "stages": {
            "layer1": layer1_agg,
            "classifier": cls_agg,
        },
        "study_best": {k: {"value": v[0], "tool": v[1]} for k, v in STUDY_BEST.items()},
    }
    with open(run_dir / "metrics_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    with open(run_dir / "metrics_layer1.json", "w") as f:
        json.dump(layer1_agg["total"], f, indent=2)
    with open(run_dir / "metrics_classifier.json", "w") as f:
        json.dump(cls_agg["total"], f, indent=2)
    with open(run_dir / "SUMMARY.md", "w") as f:
        f.write("```\n" + text + "\n```\n")

    if show_legend:
        _print_legend()


def cmd_compare(run_a: Path, run_b: Path):
    """Side-by-side diff of two runs' classifier metrics."""
    a = json.load(open(run_a / "metrics_summary.json"))
    b = json.load(open(run_b / "metrics_summary.json"))
    A = a["stages"]["classifier"]["total"]
    B = b["stages"]["classifier"]["total"]
    print(f"A = {run_a.name}")
    print(f"B = {run_b.name}")
    print()
    print(f"{'metric':<8} {'A':>8} {'B':>8} {'Δ':>8}")
    for k in ["F1", "P", "R", "Acc", "NMR"]:
        delta = B[k] - A[k]
        if k in ("Acc", "NMR"):
            print(f"{k:<8} {A[k]*100:>7.1f}% {B[k]*100:>7.1f}% {delta*100:>+7.1f}pp")
        else:
            print(f"{k:<8} {A[k]:>8.3f} {B[k]:>8.3f} {delta:>+8.3f}")


def main():
    # ============================================================
    # Edit this block to control what gets reported.
    # ============================================================
    RUN_DIR = "latest"          # "latest" or e.g. "data/runs/program_..."
    SHOW_LEGEND = False         # print Chinese legend at the end
    WORKERS = 8
    # Compare two runs (set both to skip normal report and just diff):
    COMPARE_A = None            # e.g. "data/runs/run_a"
    COMPARE_B = None            # e.g. "data/runs/run_b"
    # ============================================================

    if COMPARE_A and COMPARE_B:
        cmd_compare(Path(COMPARE_A), Path(COMPARE_B))
        return

    run_dir = _latest_run() if RUN_DIR == "latest" else Path(RUN_DIR)
    cmd_report(run_dir, workers=WORKERS, show_legend=SHOW_LEGEND)


if __name__ == "__main__":
    main()
