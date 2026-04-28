"""Phase 2 Step 2: LLM-based start-point identification with binary search.

For each CVE that program analysis couldn't resolve:
1. Compute unique code states in the candidate range
2. Binary search on states to find the vulnerability boundary
3. Each LLM call gets the SPECIFIC function body, not a vague code window

Usage:
    OPENAI_API_KEY=... python run_llm_phase2.py --all --limit 20
    python run_llm_phase2.py --cve CVE-2022-1473
    python run_llm_phase2.py --all --dry-run   # show evidence without calling API
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

from tqdm import tqdm

from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from vara.tag_filter import filter_release_tags
from pipeline.core import layer1
from pipeline.vuln_classifier import classify_version
from pipeline.line_filter import is_meaningful_line
from pipeline.state_dedup import build_unique_states, UniqueState
from pipeline.llm_judge import build_evidence, judge_version, _build_user_message, SYSTEM_PROMPT
from pipeline.path_resolver import resolve_path

DATASET_PATH = "evaluation/benchmark/Dataset_amended.json"
RESULTS_PATH = "data/reports/llm_phase2.jsonl"
REPOS = ["FFmpeg", "ImageMagick", "curl", "httpd", "openjpeg", "openssl", "qemu", "wireshark"]


def _load_env(path: str = ".env") -> None:
    if not Path(path).exists():
        return
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and val and key not in os.environ:
                os.environ[key] = val


def _binary_search_boundary(
    states: List[UniqueState],
    repo: GitRepo,
    cve_id: str,
    repo_name: str,
    patch,
    model: str,
    dry_run: bool,
) -> Tuple[Optional[int], List[Dict]]:
    """Find the earliest VULN state using sampling + binary search.

    The UNCLEAR states may contain a VULN region in the middle:
      SAFE...SAFE, VULN...VULN, SAFE...SAFE
    (left = feature not yet implemented, right = fix already applied)

    Strategy:
      1. Sample 3-4 points to find ANY VULN state
      2. Once found, binary search LEFT from there to find the earliest VULN

    Returns (boundary_index, list_of_llm_calls).
    """
    n = len(states)
    if n == 0:
        return None, []

    calls = []
    verdicts: Dict[int, str] = {}

    def probe(idx: int) -> str:
        if idx in verdicts:
            return verdicts[idx]
        state = states[idx]
        tag = state.representative_tag
        ev = build_evidence(repo, cve_id, repo_name, patch, tag)

        if dry_run:
            msg = _build_user_message(ev)
            result = {
                "tag": tag, "state_idx": idx, "verdict": "DRY_RUN",
                "msg_chars": len(msg), "functions": list(ev.functions.keys()),
            }
            calls.append(result)
            verdicts[idx] = "DRY_RUN"
            return "DRY_RUN"

        result = judge_version(ev, model=model)
        result["tag"] = tag
        result["state_idx"] = idx
        calls.append(result)
        v = result.get("verdict", "ERROR")
        verdicts[idx] = v
        return v

    # Pre-filter states: only sample states where the patched file(s) exist.
    # Rationale: if the file doesn't exist at this state, the vulnerability
    # (which lives in that file) can't exist either — so it's trivially SAFE
    # and wastes an LLM call. This also solves the "narrow VULN window" problem
    # for CVEs where the file was introduced mid-candidate-range.
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    states_with_file: List[int] = []
    for idx, s in enumerate(states):
        if any(s.file_contents.get(p) is not None for p in file_paths):
            states_with_file.append(idx)

    # If no state has the file at original path, try to resolve
    if not states_with_file:
        for idx, s in enumerate(states):
            for fp in patch.file_patches:
                path = fp.old_path or fp.new_path
                if not path:
                    continue
                rp = resolve_path(repo, fp, s.representative_tag)
                if rp.path and repo.find_file_at_version(s.representative_tag, rp.path):
                    states_with_file.append(idx)
                    break

    # If still nothing, fall back to all states
    if not states_with_file:
        states_with_file = list(range(n))

    # Step 1: Sample to find any VULN state — prefer states where the file exists.
    # Sample at 4 points spread across the file-exists states, including the
    # EARLIEST file-exists state (which is often VULN for add-only fixes where
    # the file was introduced mid-range).
    found_vuln_idx = None
    m = len(states_with_file)
    if m >= 5:
        sample_points = [states_with_file[4*m//5],
                         states_with_file[2*m//5],
                         states_with_file[m//5],
                         states_with_file[0]]  # earliest file-exists
    elif m >= 3:
        sample_points = [states_with_file[m-1],
                         states_with_file[m//2],
                         states_with_file[0]]
    elif m >= 2:
        sample_points = [states_with_file[m-1], states_with_file[0]]
    else:
        sample_points = [states_with_file[0]]

    for idx in sample_points:
        v = probe(idx)
        if v == "VULN":
            found_vuln_idx = idx
            break

    if dry_run:
        return None, calls

    # If sampling found nothing, try a few more points
    if found_vuln_idx is None:
        # Try rightmost and leftmost
        for idx in [n - 1, 0]:
            if idx not in verdicts:
                v = probe(idx)
                if v == "VULN":
                    found_vuln_idx = idx
                    break

    if found_vuln_idx is None:
        # No VULN found anywhere — give up
        return None, calls

    # Step 2: Binary search LEFT from found_vuln_idx to find earliest VULN.
    left, right = 0, found_vuln_idx
    while left < right:
        mid = (left + right) // 2
        v = probe(mid)
        if v == "VULN":
            right = mid
        elif v == "SAFE":
            left = mid + 1
        else:
            # UNCLEAR: assume SAFE (conservative) and search right
            left = mid + 1

    return right, calls


def process_cve(
    cve_id: str,
    entry: Dict,
    model: str,
    dry_run: bool,
) -> Optional[Dict]:
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

    # Phase 1
    candidates = layer1(repo, patch, release_set)
    if not candidates:
        return None

    # Phase 2 Step 1 (with Phase 1.5 path resolution)
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    br = repo.batch_get_files([(t, p) for t in candidates for p in file_paths])

    # Pre-resolve missing paths
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

    # Classify each candidate
    step1_vuln = set()
    step1_unclear = set()
    for tag in candidates:
        fc = {p: br.get((tag, p)) for p in file_paths}
        cls, _ = classify_version(fc, patch)
        if cls == "VULN":
            step1_vuln.add(tag)
        else:
            step1_unclear.add(tag)

    # Build unique states for UNCLEAR tags
    states = build_unique_states(repo, patch, step1_unclear, tag_order)
    repo.flush_cache()

    # If program already found everything, skip
    if not states and step1_vuln:
        all_vuln = step1_vuln
    elif not states:
        return {"cve": cve_id, "repo": repo_name, "case": "NO_CANDIDATES"}
    else:
        # Binary search on states
        boundary_idx, llm_calls = _binary_search_boundary(
            states, repo, cve_id, repo_name, patch, model, dry_run,
        )

        # Collect VULN tags from LLM results
        step2_vuln = set()
        if boundary_idx is not None:
            for s in states[boundary_idx:]:
                step2_vuln.update(s.tags)

        all_vuln = step1_vuln | step2_vuln

    if not all_vuln:
        return {
            "cve": cve_id, "repo": repo_name, "case": "NO_VULN",
            "states": len(states),
            "llm_calls": llm_calls if 'llm_calls' in dir() else [],
        }

    # Compare with GT
    vuln_sorted = sorted(all_vuln, key=lambda t: tag_order.get(t, 10**9))
    gt_in_release = gt & release_set
    gt_sorted = sorted(gt_in_release, key=lambda t: tag_order.get(t, 10**9))

    if not gt_sorted:
        return {
            "cve": cve_id, "repo": repo_name, "case": "NO_GT",
            "total_vuln": len(all_vuln),
        }

    dist = tag_order.get(vuln_sorted[0], 10**9) - tag_order.get(gt_sorted[0], 10**9)
    case = "EXACT" if dist == 0 else ("SAFE" if dist > 0 else "EARLY")

    return {
        "cve": cve_id, "repo": repo_name, "case": case, "dist": dist,
        "our_earliest": vuln_sorted[0], "gt_earliest": gt_sorted[0],
        "step1_vuln": len(step1_vuln),
        "step2_vuln": len(all_vuln - step1_vuln),
        "states_checked": len(states),
        "llm_calls": llm_calls if 'llm_calls' in dir() else [],
        "total_vuln": len(all_vuln), "gt_count": len(gt_sorted),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve", help="Single CVE")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cases", default="SAFE,EARLY,NOVULN,NO_VULN")
    ap.add_argument("--workers", type=int, default=8,
                    help="Concurrent LLM calls (default: 8)")
    args = ap.parse_args()

    _load_env()
    if args.model is None:
        args.model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    if not args.cve and not args.all:
        ap.print_help()
        sys.exit(1)

    with open(DATASET_PATH) as f:
        dataset = json.load(f)

    if args.cve:
        targets = [(args.cve, dataset[args.cve])]
    else:
        targets = [(cid, e) for cid, e in dataset.items() if e["repo"] in REPOS]

    # Load already-done CVEs for resumability
    done = set()
    if not args.cve and Path(RESULTS_PATH).exists():
        with open(RESULTS_PATH) as f:
            for line in f:
                try:
                    done.add(json.loads(line)["cve"])
                except (json.JSONDecodeError, KeyError):
                    pass

    pending = [(c, e) for c, e in targets if c not in done]
    if args.limit:
        pending = pending[:args.limit]

    if args.cve or len(pending) == 1 or args.workers <= 1:
        processed = 0
        for cve_id, entry in tqdm(pending, desc="LLM Phase 2"):
            try:
                rec = process_cve(cve_id, entry, model=args.model, dry_run=args.dry_run)
            except Exception as e:
                rec = {"cve": cve_id, "repo": entry.get("repo"), "error": repr(e)}
            if rec is None:
                continue
            if args.cve:
                print(json.dumps(rec, indent=2))
            else:
                Path(RESULTS_PATH).parent.mkdir(parents=True, exist_ok=True)
                with open(RESULTS_PATH, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            processed += 1
    else:
        Path(RESULTS_PATH).parent.mkdir(parents=True, exist_ok=True)
        write_lock = Lock()
        processed = 0

        def _run(cve_id, entry):
            try:
                rec = process_cve(cve_id, entry, model=args.model, dry_run=args.dry_run)
            except Exception as e:
                rec = {"cve": cve_id, "repo": entry.get("repo"), "error": repr(e)}
            return rec

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(_run, c, e): c for c, e in pending}
            for future in tqdm(as_completed(futures), total=len(futures), desc="LLM Phase 2"):
                rec = future.result()
                if rec is None:
                    continue
                with write_lock:
                    with open(RESULTS_PATH, "a") as f:
                        f.write(json.dumps(rec) + "\n")
                processed += 1

    # Summary
    if not args.cve and processed > 0:
        results = []
        with open(RESULTS_PATH) as f:
            for line in f:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        cases = Counter(r.get("case") for r in results)
        measured = cases.get("EXACT", 0) + cases.get("SAFE", 0) + cases.get("EARLY", 0)
        print(f"\n{'='*60}")
        print(f"LLM Phase 2 — {len(results)} CVEs — model={args.model}")
        print(f"{'='*60}")
        for c in ["EXACT", "SAFE", "EARLY", "NO_VULN", "NO_GT", "NO_CANDIDATES"]:
            if cases.get(c, 0) > 0:
                pct = f" ({cases[c]/measured*100:.1f}%)" if measured and c in ("EXACT","SAFE","EARLY") else ""
                print(f"  {c}: {cases[c]}{pct}")
        if measured:
            print(f"\n  EXACT+SAFE: {(cases.get('EXACT',0)+cases.get('SAFE',0))/measured*100:.1f}%")

    print(f"\nDone. {processed} CVEs processed.")


if __name__ == "__main__":
    main()
