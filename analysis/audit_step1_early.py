"""Audit Step 1 EARLY cases: is the code at our_earliest same as gt_earliest?

If yes → GT likely too narrow (and our Step 1 is actually correct)
If no → Step 1 has a real FP (textual match but different semantic)
"""

import json
import hashlib
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1
from app.phase2.classifier import classify_version
from app.phase1.path_resolver import resolve_path


def _content_hash(content):
    # Normalize whitespace for robust comparison
    import re
    if content is None:
        return None
    # Collapse whitespace and remove blank lines
    normalized = re.sub(r'\s+', ' ', content).strip()
    return hashlib.md5(normalized.encode('utf-8', errors='replace')).hexdigest()


def process(args):
    cve_id, entry = args
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
        if not gt:
            return None

        file_paths = [fp.old_path or fp.new_path for fp in patch.file_patches if (fp.old_path or fp.new_path)]
        br = repo.batch_get_files([(t, p) for t in candidates for p in file_paths])

        # Phase 1.5
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

        step1_vuln = set()
        for tag in candidates:
            fc = {p: br.get((tag, p)) for p in file_paths}
            cls, _ = classify_version(fc, patch)
            if cls == 'VULN':
                step1_vuln.add(tag)

        if not step1_vuln:
            return None

        gt_in = gt & release_set
        our_sorted = sorted(step1_vuln, key=lambda t: tag_order.get(t, 10 ** 9))
        gt_sorted = sorted(gt_in, key=lambda t: tag_order.get(t, 10 ** 9))
        if not gt_sorted:
            return None

        our_earliest = our_sorted[0]
        gt_earliest = gt_sorted[0]
        dist = tag_order.get(our_earliest, 10 ** 9) - tag_order.get(gt_earliest, 10 ** 9)

        if dist >= 0:
            return None  # EXACT or SAFE, not EARLY

        # EARLY case — compare file content hashes
        our_content = {}
        gt_content = {}
        for p in file_paths:
            our_content[p] = br.get((our_earliest, p))
            gt_content[p] = br.get((gt_earliest, p))

        # Compare content
        same_hash = all(
            _content_hash(our_content.get(p)) == _content_hash(gt_content.get(p))
            for p in file_paths
        )

        # Compare deleted line match counts
        our_del_matches = 0
        gt_del_matches = 0
        total_del = 0
        for fp in patch.file_patches:
            path = fp.old_path or fp.new_path
            if not path:
                continue
            our_c = our_content.get(path) or ''
            gt_c = gt_content.get(path) or ''
            for line in fp.all_deleted_lines:
                s = line.strip()
                if len(s) < 10:
                    continue
                total_del += 1
                if s in our_c:
                    our_del_matches += 1
                if s in gt_c:
                    gt_del_matches += 1

        return {
            'cve': cve_id,
            'repo': entry['repo'],
            'dist': dist,
            'our_earliest': our_earliest,
            'gt_earliest': gt_earliest,
            'same_content': same_hash,
            'our_del_matches': our_del_matches,
            'gt_del_matches': gt_del_matches,
            'total_del': total_del,
            'candidate_count': len(candidates),
            'step1_vuln_count': len(step1_vuln),
            'gt_count': len(gt_in),
        }
    except Exception as ex:
        return {'cve': cve_id, 'error': repr(ex)[:100]}


def main():
    dataset = json.load(open('benchmark/Dataset_amended.json'))
    repos = ['FFmpeg', 'ImageMagick', 'curl', 'httpd', 'openjpeg', 'openssl', 'qemu', 'wireshark']
    args = [(cid, e) for cid, e in dataset.items() if e.get('repo') in repos]

    results = []
    with ProcessPoolExecutor(max_workers=12) as ex:
        for r in ex.map(process, args):
            if r and 'error' not in r:
                results.append(r)

    # Classify: same_content (GT likely wrong) vs not
    same = [r for r in results if r['same_content']]
    diff = [r for r in results if not r['same_content']]

    print(f"Total Step 1 EARLY cases: {len(results)}")
    print(f"  Code IDENTICAL at our and gt: {len(same)}  ← likely GT too narrow")
    print(f"  Code DIFFERS:                  {len(diff)}  ← real FP or code evolved")

    print(f"\n=== IDENTICAL code (GT likely too narrow) — top 20 by |dist| ===")
    same.sort(key=lambda x: x['dist'])  # most negative first
    print(f"{'CVE':<22} {'Repo':<12} {'Dist':>5} {'Our':>22} {'GT':>22}")
    for r in same[:25]:
        print(f"{r['cve']:<22} {r['repo']:<12} {r['dist']:>5} {r['our_earliest']:>22} {r['gt_earliest']:>22}")

    print(f"\n=== By repo ===")
    by_repo = defaultdict(lambda: [0, 0])
    for r in results:
        by_repo[r['repo']][0 if r['same_content'] else 1] += 1
    print(f'{"Repo":<12} {"Same":>6} {"Diff":>6} {"Total":>6}')
    for repo in sorted(by_repo):
        s, d = by_repo[repo]
        print(f'{repo:<12} {s:>6} {d:>6} {s+d:>6}')

    # Save
    with open('data/analysis/step1_early_audit.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved {len(results)} records to data/analysis/step1_early_audit.json")


if __name__ == '__main__':
    main()
