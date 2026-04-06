"""Analyze SAFE and EARLY cases in detail."""
import json, sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from pipeline.core import layer1
from pipeline.vuln_classifier import classify_version, normalize, _find_context_position
from pipeline.line_filter import is_meaningful_line
from vara.tag_filter import filter_release_tags
from tqdm import tqdm

REPOS = ['curl', 'openssl', 'FFmpeg', 'qemu', 'wireshark', 'ImageMagick', 'httpd', 'openjpeg']


def analyze_cve(args):
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

    has_md = any(is_meaningful_line(l) for fp in patch.file_patches for l in fp.all_deleted_lines)
    gt = set(entry['affected_version'])
    if not has_md or not gt:
        return None

    l1 = layer1(repo, patch, release_set)
    file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
    br = repo.batch_get_files([(t, p) for t in l1 for p in file_paths])
    repo.flush_cache()

    vuln_tags = []
    for tag in l1:
        fc = {p: br.get((tag, p)) for p in file_paths}
        cls, _ = classify_version(fc, patch)
        if cls == 'VULN':
            vuln_tags.append(tag)

    if not vuln_tags:
        return None

    vs = sorted(vuln_tags, key=lambda t: tag_order.get(t, 9999))
    gs = sorted(gt, key=lambda t: tag_order.get(t, 9999))
    dist = tag_order.get(vs[0], 9999) - tag_order.get(gs[0], 9999)

    if dist == 0:
        return None  # EXACT

    gt_tag = gs[0]
    early_tag = vs[0]
    md_total = sum(len([l for l in fp.all_deleted_lines if is_meaningful_line(l)]) for fp in patch.file_patches)

    # Analyze GT version
    ga = {'global_match': 0, 'context_found': False, 'file_exists': True, 'total_md': md_total}
    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if not path: continue
        md = [l for l in fp.all_deleted_lines if is_meaningful_line(l)]
        if not md: continue
        content = br.get((gt_tag, path))
        if content is None:
            content = repo.find_file_at_version(gt_tag, path)
        if content is None:
            ga['file_exists'] = False
            continue
        content_lines = content.splitlines()
        cn = set(normalize(l) for l in content_lines)
        ga['global_match'] = sum(1 for l in md if normalize(l) in cn)
        for hunk in fp.hunks:
            if hunk.context_lines:
                pos = _find_context_position(content_lines, hunk.context_lines)
                if pos is not None:
                    ga['context_found'] = True
                break
        break

    # For EARLY: compare early and GT versions
    ea = {}
    if dist < 0:
        for fp in patch.file_patches:
            path = fp.old_path or fp.new_path
            if not path: continue
            md = [l for l in fp.all_deleted_lines if is_meaningful_line(l)]
            if not md: continue
            ce = br.get((early_tag, path))
            cg = br.get((gt_tag, path))
            if ce and cg:
                en = set(normalize(l) for l in ce.splitlines())
                gn = set(normalize(l) for l in cg.splitlines())
                ea['early_match'] = sum(1 for l in md if normalize(l) in en)
                ea['gt_match'] = sum(1 for l in md if normalize(l) in gn)
                ea['same_file'] = (ce == cg)
            elif ce and not cg:
                ea['gt_file_missing'] = True
            break

    return {
        'cve': cve_id, 'repo': repo_name,
        'category': 'SAFE' if dist > 0 else 'EARLY',
        'dist': dist, 'early_tag': early_tag, 'gt_tag': gt_tag,
        'md': md_total, 'gt_analysis': ga, 'early_analysis': ea,
    }


def main():
    with open('evaluation/benchmark/Dataset_amended.json') as f:
        dataset = json.load(f)

    entries = [(cve_id, entry) for cve_id, entry in dataset.items() if entry['repo'] in REPOS]

    results = []
    with ProcessPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(analyze_cve, e): e for e in entries}
        for future in tqdm(as_completed(futures), total=len(futures), desc='Analyzing'):
            r = future.result()
            if r:
                results.append(r)

    with open('data/reports/phase2_analysis.json', 'w') as f:
        json.dump(results, f, indent=2)

    safe = [r for r in results if r['category'] == 'SAFE']
    early = [r for r in results if r['category'] == 'EARLY']

    print(f'\n{"="*80}')
    print(f'SAFE: {len(safe)} CVEs')
    print(f'{"="*80}')
    safe_reasons = []
    for r in safe:
        ga = r['gt_analysis']
        ratio = ga['global_match'] / ga['total_md'] if ga['total_md'] > 0 else 0
        if not ga['file_exists']:
            reason = 'file_not_found'
        elif ratio > 0.5 and ga['context_found']:
            reason = 'del_in_file+context_found'
        elif ratio > 0.5:
            reason = 'del_in_file+no_context'
        elif ratio > 0:
            reason = 'del_partial'
        else:
            reason = 'del_absent'
        safe_reasons.append(reason)
        r['reason'] = reason

    for reason, count in Counter(safe_reasons).most_common():
        cases = [r for r in safe if r['reason'] == reason]
        avg_d = sum(c['dist'] for c in cases) / len(cases)
        print(f'  {reason}: {count} (avg dist={avg_d:.0f})')
        for c in cases[:3]:
            ga = c['gt_analysis']
            print(f'    {c["cve"]} ({c["repo"]}): dist={c["dist"]} match={ga["global_match"]}/{ga["total_md"]}')

    print(f'\n{"="*80}')
    print(f'EARLY: {len(early)} CVEs')
    print(f'{"="*80}')
    for r in early:
        ea = r['early_analysis']
        if ea.get('gt_file_missing'):
            r['reason'] = 'gt_file_missing'
        elif ea.get('same_file'):
            r['reason'] = 'same_code(GT_error?)'
        elif ea.get('early_match', 0) > 0 and ea.get('gt_match', 0) > 0:
            r['reason'] = 'both_match_diff_code'
        elif ea.get('early_match', 0) > 0:
            r['reason'] = 'only_early_matches'
        else:
            r['reason'] = 'unknown'

    for reason, count in Counter(r['reason'] for r in early).most_common():
        cases = [r for r in early if r['reason'] == reason]
        print(f'  {reason}: {count}')
        for c in cases[:3]:
            print(f'    {c["cve"]} ({c["repo"]}): dist={c["dist"]} early={c["early_tag"]} gt={c["gt_tag"]}')

    sys.stdout.flush()


if __name__ == '__main__':
    main()
