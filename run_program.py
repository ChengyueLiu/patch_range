"""Program-only pipeline: Phase 1 + Phase 1.5 + Phase 2 Step 1.

Runs the full deterministic pipeline (no LLM) on the benchmark and saves
per-CVE results plus a summary to data/runs/<name>/.

Edit the config block at the top of main() to control what gets run.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1
from app.phase1.path_resolver import resolve_path
from app.phase2.classifier import classify_version
from app.runner import run_pipeline

DATASET_PATH = "benchmark/Dataset_amended.json"
RUNS_DIR = "data/runs"


def _make_run_dir(name=None):
    slug = name or "program_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(RUNS_DIR) / slug
    out.mkdir(parents=True, exist_ok=True)
    return out


def _git_head() -> str:
    """Current code HEAD short hash (best effort) — recorded in config.json."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "?"


def process_cve(args):
    cve_id, entry = args
    repo_name = entry["repo"]
    repo = GitRepo(f"data/repos/{repo_name}")

    release_tags = filter_release_tags(repo.get_all_tags())
    release_set = set(release_tags)
    tag_order = {t: i for i, t in enumerate(release_tags)}

    commits = [c for g in entry["fixing_commits"] for c in g]
    patch = parse_commits(repo, commits)
    if not patch.file_patches:
        return None

    gt = set(entry.get("affected_version", []))

    # Phase 1 stats (run_pipeline does Layer 1 + 2 + 3)
    p1 = run_pipeline(repo, patch, cve_id, repo_name, list(gt))

    # Phase 2 Step 1 with Phase 1.5 path resolution
    candidates = layer1(repo, patch, release_set)
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    br = repo.batch_get_files([(t, p) for t in candidates for p in file_paths])

    resolved = {}
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if not path:
            continue
        if any(br.get((t, path)) is None for t in list(candidates)[:3]):
            for t in candidates:
                if br.get((t, path)) is None:
                    rp = resolve_path(repo, fp, t)
                    if rp.path and rp.path != path:
                        resolved[path] = rp.path
                    break
    if resolved:
        alt_br = repo.batch_get_files([(t, rp) for t in candidates for rp in resolved.values()])
        for (tag, alt_path), content in alt_br.items():
            for orig, alt in resolved.items():
                if alt == alt_path and br.get((tag, orig)) is None and content is not None:
                    br[(tag, orig)] = content
                    break

    vuln_tags = []
    for tag in candidates:
        fc = {p: br.get((tag, p)) for p in file_paths}
        cls, _ = classify_version(fc, patch)
        if cls == "VULN":
            vuln_tags.append(tag)
    repo.flush_cache()

    gt_in = gt & release_set

    # Layer 1 earliest: predict ALL candidates as VULN (the high-recall upper bound)
    layer1_earliest = (sorted(candidates, key=lambda t: tag_order.get(t, 10**9))[0]
                       if candidates else None)

    if not vuln_tags:
        case = "NO_VULN"
        our_e = None
    elif not gt_in:
        case = "NO_GT"
        our_e = sorted(vuln_tags, key=lambda t: tag_order.get(t, 10**9))[0]
    else:
        vs = sorted(vuln_tags, key=lambda t: tag_order.get(t, 10**9))
        gs = sorted(gt_in, key=lambda t: tag_order.get(t, 10**9))
        dist = tag_order.get(vs[0], 10**9) - tag_order.get(gs[0], 10**9)
        our_e = vs[0]
        case = "EXACT" if dist == 0 else ("SAFE" if dist > 0 else "EARLY")

    rec = {
        "cve": cve_id, "repo": repo_name, "case": case,
        "our_earliest": our_e,
        "layer1_earliest": layer1_earliest,
        "gt_earliest": (sorted(gt_in, key=lambda t: tag_order.get(t, 10**9))[0]
                        if gt_in else None),
        "candidate_count": len(candidates),
        "vuln_count": len(vuln_tags),
        "gt_count": len(gt_in),
        "phase1_stats": {
            "total_tags": p1.total_tags,
            "after_prefilter": p1.after_prefilter,
            "after_layer1": p1.after_layer1,
            "after_layer2": p1.after_layer2,
            "unique_states": p1.unique_states,
            "gt_covered_by_layer1": p1.gt_covered_by_layer1,
            "gt_covered_by_layer2": p1.gt_covered_by_layer2,
        },
    }
    if case in {"EXACT", "SAFE", "EARLY"} and our_e and rec["gt_earliest"]:
        rec["dist"] = tag_order.get(our_e, 10**9) - tag_order.get(rec["gt_earliest"], 10**9)
    return rec


def main():
    # ============================================================
    # Edit this block to control what gets run.
    # ============================================================
    REPOS = ["FFmpeg", "ImageMagick", "curl", "httpd",
             "openjpeg", "openssl", "qemu", "wireshark"]
    PER_REPO_LIMIT = 10        # 0 = no limit
    GLOBAL_LIMIT = 0           # 0 = no limit (ignored if PER_REPO_LIMIT > 0)
    WORKERS = 12
    NAME = None                # None = auto timestamp ("program_YYYYmmdd_HHMMSS")
    SINGLE_CVE = None          # if set (e.g. "CVE-2020-12284"), only run this one and print
    # ============================================================

    with open(DATASET_PATH) as f:
        dataset = json.load(f)

    if SINGLE_CVE:
        rec = process_cve((SINGLE_CVE, dataset[SINGLE_CVE]))
        print(json.dumps(rec, indent=2))
        return

    targets = [(cid, e) for cid, e in dataset.items() if e["repo"] in REPOS]

    if PER_REPO_LIMIT > 0:
        seen_per_repo: dict = {}
        selected = []
        for cid, e in targets:
            r = e["repo"]
            if seen_per_repo.get(r, 0) < PER_REPO_LIMIT:
                selected.append((cid, e))
                seen_per_repo[r] = seen_per_repo.get(r, 0) + 1
        targets = selected
    elif GLOBAL_LIMIT > 0:
        targets = targets[:GLOBAL_LIMIT]

    run_dir = _make_run_dir(NAME)
    results_path = run_dir / "results.jsonl"

    config = {
        "repos": REPOS,
        "per_repo_limit": PER_REPO_LIMIT,
        "global_limit": GLOBAL_LIMIT,
        "workers": WORKERS,
        "dataset": DATASET_PATH,
        "code_git_head": _git_head(),
        "n_targets": len(targets),
        "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    with open(run_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    repo_count = len({e["repo"] for _, e in targets})
    print(f"Run dir: {run_dir}")
    print(f"Targets: {len(targets)} CVEs across {repo_count} repos")

    results = []
    with ProcessPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(process_cve, t): t for t in targets}
        with open(results_path, "w") as f_out:
            for fut in tqdm(as_completed(futures), total=len(futures), desc="program"):
                rec = fut.result()
                if rec is None:
                    continue
                f_out.write(json.dumps(rec) + "\n")
                results.append(rec)

    # Quick summary (case-level only — full R/P/F1 is in report.py)
    cases = Counter(r["case"] for r in results)
    measured = cases["EXACT"] + cases["SAFE"] + cases["EARLY"]
    print()
    print(f"=== Program pipeline — {len(results)} CVEs ===")
    for c in ["EXACT", "SAFE", "EARLY", "NO_VULN", "NO_GT"]:
        if cases.get(c, 0):
            pct = f" ({cases[c]/measured*100:.1f}%)" if measured and c in {"EXACT", "SAFE", "EARLY"} else ""
            print(f"  {c}: {cases[c]}{pct}")
    if measured:
        print(f"  EXACT+SAFE: {(cases['EXACT']+cases['SAFE'])/measured*100:.1f}%")
    print(f"\nResults saved to: {run_dir}")
    print(f"  Edit report.py and run it to see R/P/F1 per stage")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
