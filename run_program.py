"""Full analysis: Phase 1 + Phase 2 Step 1 for all CVEs."""

from __future__ import annotations

import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from pipeline.core import layer1, run_pipeline
from pipeline.vuln_classifier import classify_version
from pipeline.line_filter import is_meaningful_line
from vara.tag_filter import filter_release_tags
from tqdm import tqdm

DATASET_PATH = "evaluation/benchmark/Dataset_amended.json"
REPOS = ['FFmpeg', 'ImageMagick', 'curl', 'httpd', 'openjpeg', 'openssl', 'qemu', 'wireshark']
NUM_WORKERS = 12


def process_cve(args):
    cve_id, entry = args
    repo_name = entry['repo']
    repo = GitRepo(f'data/repos/{repo_name}')
    release_tags = filter_release_tags(repo.get_all_tags())
    release_set = set(release_tags)
    tag_order = {t: i for i, t in enumerate(release_tags)}

    commits = [c for g in entry['fixing_commits'] for c in g]
    patch = parse_commits(repo, commits)
    if not patch.file_patches:
        return None

    gt = set(entry['affected_version'])

    p1 = run_pipeline(repo, patch, cve_id, repo_name, list(gt))
    repo.flush_cache()

    p2 = {'repo': repo_name, 'cve_id': cve_id}

    has_md = any(is_meaningful_line(l) for fp in patch.file_patches for l in fp.all_deleted_lines)

    if not has_md:
        p2['type'] = 'no_vuln'
        return (p1, p2)
    if not gt:
        p2['type'] = 'no_gt'
        return (p1, p2)

    l1 = layer1(repo, patch, release_set)
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    br = repo.batch_get_files([(t, p) for t in l1 for p in file_paths])

    # Phase 1.5: pre-resolve any missing file paths (once per file, not per tag)
    from pipeline.path_resolver import resolve_path
    resolved = {}  # original_path -> resolved_path
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if not path:
            continue
        # Check if file is missing at any candidate tag
        if any(br.get((t, path)) is None for t in list(l1)[:3]):
            # Try to resolve using one of the tags where it's missing
            for t in l1:
                if br.get((t, path)) is None:
                    rp = resolve_path(repo, fp, t)
                    if rp.path and rp.path != path:
                        resolved[path] = rp.path
                    break

    # If we found alternative paths, batch-read them too
    if resolved:
        alt_requests = [(t, rp) for t in l1 for _, rp in resolved.items()]
        alt_br = repo.batch_get_files(alt_requests)
        for (tag, alt_path), content in alt_br.items():
            # Find the original path that mapped to this alt_path
            for orig, alt in resolved.items():
                if alt == alt_path:
                    if br.get((tag, orig)) is None and content is not None:
                        br[(tag, orig)] = content
                    break

    vuln_tags = []
    for tag in l1:
        fc = {p: br.get((tag, p)) for p in file_paths}
        cls, _ = classify_version(fc, patch)
        if cls == "VULN":
            vuln_tags.append(tag)

    if not vuln_tags:
        p2['type'] = 'no_vuln'
        return (p1, p2)

    vuln_sorted = sorted(vuln_tags, key=lambda t: tag_order.get(t, 9999))
    gt_sorted = sorted(gt, key=lambda t: tag_order.get(t, 9999))

    dist = tag_order.get(vuln_sorted[0], 9999) - tag_order.get(gt_sorted[0], 9999)

    if dist == 0:
        p2['type'] = 'exact'
    elif dist > 0:
        p2['type'] = 'safe'
        p2['dist'] = dist
    else:
        p2['type'] = 'early'
        p2['dist'] = dist

    return (p1, p2)


def main():
    import sys

    with open(DATASET_PATH) as f:
        dataset = json.load(f)

    entries = [(cve_id, entry) for cve_id, entry in dataset.items() if entry['repo'] in REPOS]

    p1_results = defaultdict(list)
    p2_results = defaultdict(lambda: {'exact': 0, 'safe': 0, 'early': 0, 'no_vuln': 0, 'no_gt': 0,
                                       'safe_dists': [], 'total': 0})

    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = {executor.submit(process_cve, e): e for e in entries}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Full analysis", unit="CVE"):
            result = future.result()
            if result is None:
                continue
            p1, p2 = result
            repo_name = p2['repo']
            p1_results[repo_name].append(p1)
            p2_results[repo_name]['total'] += 1

            t = p2['type']
            if t == 'exact': p2_results[repo_name]['exact'] += 1
            elif t == 'safe':
                p2_results[repo_name]['safe'] += 1
                p2_results[repo_name]['safe_dists'].append(p2['dist'])
            elif t == 'early': p2_results[repo_name]['early'] += 1
            elif t == 'no_vuln': p2_results[repo_name]['no_vuln'] += 1
            elif t == 'no_gt': p2_results[repo_name]['no_gt'] += 1

    # Print Phase 1
    sys.stdout.flush()
    print()
    print("=" * 100)
    print("VARA PIPELINE FULL RESULTS")
    print("=" * 100)
    print()
    print("Phase 1: Candidate Range")
    print("-" * 100)
    print(f"  {'Repo':<15} {'#CVE':>5} {'Total':>7} {'PreFilt':>8} {'Layer1':>7} {'Layer2':>7} "
          f"{'States':>7} {'GT':>7} {'L1Cov%':>7} {'L2Cov%':>7}")
    print("  " + "-" * 93)

    for repo_name in REPOS:
        results = p1_results[repo_name]
        if not results: continue
        n = len(results)
        s = lambda a: sum(getattr(r, a) for r in results)
        tgt = s('ground_truth')
        l1c = s('gt_covered_by_layer1') / tgt * 100 if tgt > 0 else 0
        l2c = s('gt_covered_by_layer2') / tgt * 100 if tgt > 0 else 0
        print(f"  {repo_name:<15} {n:>5} {s('total_tags')//n:>7} {s('after_prefilter')//n:>8} "
              f"{s('after_layer1')//n:>7} {s('after_layer2')//n:>7} {s('unique_states')//n:>7} "
              f"{s('ground_truth')//n:>7} {l1c:>6.1f}% {l2c:>6.1f}%")

    # Print Phase 2
    print()
    print("Phase 2 Step 1: Start Point Localization")
    print("-" * 100)
    print(f"  {'Repo':<15} {'#CVE':>5} {'EXACT':>6} {'SAFE':>6} {'EARLY':>6} {'NoVuln':>7} {'AvgSafeDist':>12}")
    print("  " + "-" * 60)

    t_exact = t_safe = t_early = t_nv = t_total = 0
    all_safe_d = []

    for repo_name in REPOS:
        p2 = p2_results[repo_name]
        avg_sd = sum(p2['safe_dists']) / len(p2['safe_dists']) if p2['safe_dists'] else 0
        print(f"  {repo_name:<15} {p2['total']:>5} {p2['exact']:>6} {p2['safe']:>6} {p2['early']:>6} "
              f"{p2['no_vuln']:>7} {avg_sd:>12.1f}")
        t_exact += p2['exact']; t_safe += p2['safe']; t_early += p2['early']
        t_nv += p2['no_vuln']; t_total += p2['total']
        all_safe_d.extend(p2['safe_dists'])

    print("  " + "-" * 60)
    avg_all = sum(all_safe_d) / len(all_safe_d) if all_safe_d else 0
    print(f"  {'TOTAL':<15} {t_total:>5} {t_exact:>6} {t_safe:>6} {t_early:>6} {t_nv:>7} {avg_all:>12.1f}")

    measured = t_exact + t_safe + t_early
    if measured > 0:
        print(f"\n  EXACT: {t_exact/measured*100:.1f}% | SAFE: {t_safe/measured*100:.1f}% | EARLY: {t_early/measured*100:.1f}%")
        print(f"  EXACT+SAFE: {(t_exact+t_safe)/measured*100:.1f}%")

    print(f"\n  Remaining for LLM:")
    print(f"    SAFE (search backwards):  {t_safe} CVEs")
    print(f"    NoVuln (full search):     {t_nv} CVEs")
    print(f"    EARLY (verify):           {t_early} CVEs")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
