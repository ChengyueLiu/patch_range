"""For all EARLY cases in the last LLM run, re-run Step 1 with fixed tag ordering
and see which ones no longer look EARLY."""
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from vara.tag_filter import filter_release_tags
from pipeline.core import layer1
from pipeline.vuln_classifier import classify_version
from pipeline.path_resolver import resolve_path


def recheck(args):
    cve_id, entry, old_dist, old_our, old_gt = args
    try:
        repo = GitRepo(f'data/repos/{entry["repo"]}')
        tags = filter_release_tags(repo.get_all_tags())
        tag_order = {t: i for i, t in enumerate(tags)}
        release_set = set(tags)
        commits = [c for g in entry['fixing_commits'] for c in g]
        patch = parse_commits(repo, commits)
        if not patch.file_patches:
            return None
        candidates = layer1(repo, patch, release_set)
        gt = set(entry.get('affected_version', []))

        file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
        br = repo.batch_get_files([(t, p) for t in candidates for p in file_paths])

        # Phase 1.5
        resolved = {}
        for fp in patch.file_patches:
            path = fp.old_path or fp.new_path
            if not path: continue
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

        step1_vuln = set()
        for tag in candidates:
            fc = {p: br.get((tag, p)) for p in file_paths}
            cls, _ = classify_version(fc, patch)
            if cls == 'VULN':
                step1_vuln.add(tag)

        gt_in = gt & release_set
        if not step1_vuln or not gt_in:
            return None

        our_sorted = sorted(step1_vuln, key=lambda t: tag_order.get(t, 10**9))
        gt_sorted = sorted(gt_in, key=lambda t: tag_order.get(t, 10**9))
        new_our = our_sorted[0]
        new_gt = gt_sorted[0]
        new_dist = tag_order.get(new_our, 10**9) - tag_order.get(new_gt, 10**9)
        new_case = 'EXACT' if new_dist == 0 else ('SAFE' if new_dist > 0 else 'EARLY')
        return {'cve': cve_id, 'repo': entry['repo'],
                'old_dist': old_dist, 'new_dist': new_dist,
                'old_our': old_our, 'new_our': new_our,
                'gt': new_gt, 'new_case': new_case}
    except Exception as ex:
        return None


def main():
    dataset = json.load(open('evaluation/benchmark/Dataset_amended.json'))
    llm = [json.loads(l) for l in open('data/reports/llm_phase2.jsonl') if l.strip()]
    early = [r for r in llm if r.get('case') == 'EARLY']
    print(f"Rechecking {len(early)} EARLY cases with fixed tag ordering...")

    args = [(r['cve'], dataset[r['cve']], r['dist'], r.get('our_earliest','-'), r.get('gt_earliest','-'))
            for r in early if r['cve'] in dataset]

    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(recheck, a): a for a in args}
        for f in tqdm(as_completed(futures), total=len(futures)):
            r = f.result()
            if r: results.append(r)

    # Summary
    still_early = [r for r in results if r['new_case'] == 'EARLY']
    now_safe = [r for r in results if r['new_case'] == 'SAFE']
    now_exact = [r for r in results if r['new_case'] == 'EXACT']
    print(f"\nOf {len(results)} previously-EARLY cases:")
    print(f"  Still EARLY: {len(still_early)}")
    print(f"  Now SAFE:    {len(now_safe)}")
    print(f"  Now EXACT:   {len(now_exact)}")

    if now_exact:
        print(f"\nCases now EXACT (tag ordering fix resolved):")
        for r in now_exact[:10]:
            print(f"  {r['cve']:<22} {r['repo']:<12} was EARLY dist={r['old_dist']} our={r['old_our']}")
    if now_safe:
        print(f"\nCases now SAFE (tag ordering fix narrowed, but still off):")
        for r in now_safe[:10]:
            print(f"  {r['cve']:<22} {r['repo']:<12} dist {r['old_dist']} -> +{r['new_dist']} our {r['old_our']} -> {r['new_our']}")
    if still_early:
        print(f"\nCases still EARLY (real FP or GT issue):")
        for r in still_early:
            print(f"  {r['cve']:<22} {r['repo']:<12} dist {r['old_dist']} -> {r['new_dist']} our {r['old_our']} -> {r['new_our']} gt={r['gt']}")


if __name__ == '__main__':
    main()
