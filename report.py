"""Thread-based F1 computation (avoids macOS ProcessPool deadlock)."""
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from vara.repo import GitRepo
from vara.patch_parser import parse_commits
from vara.tag_filter import filter_release_tags
from pipeline.core import layer1
from pipeline.vuln_classifier import classify_version
from pipeline.path_resolver import resolve_path


def process_step1(entry):
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
        tp = len(step1_vuln & gt_in)
        fp = len(step1_vuln - gt_in)
        fn = len(gt_in - step1_vuln)
        return (entry['repo'], tp, fp, fn)
    except Exception as ex:
        return None


def main():
    dataset = json.load(open('evaluation/benchmark/Dataset_amended.json'))
    repos = ['FFmpeg', 'ImageMagick', 'curl', 'httpd', 'openjpeg', 'openssl', 'qemu', 'wireshark']
    targets = [(cid, e) for cid, e in dataset.items() if e.get('repo') in repos]

    repo_stats = defaultdict(lambda: [0, 0, 0])
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(process_step1, e): cid for cid, e in targets}
        for future in tqdm(as_completed(futures), total=len(futures), desc='Step1'):
            r = future.result()
            if r:
                repo, tp, fp, fn = r
                s = repo_stats[repo]
                s[0] += tp; s[1] += fp; s[2] += fn

    tot_tp = tot_fp = tot_fn = 0
    print(f'=== Step 1 F1 (with fixed tag ordering) ===')
    print(f'{"Repo":<12} {"TP":>6} {"FP":>6} {"FN":>6} {"Prec":>6} {"Rec":>6} {"F1":>6}')
    for r, (tp, fp, fn) in sorted(repo_stats.items()):
        p = tp/(tp+fp) if tp+fp else 0
        rc = tp/(tp+fn) if tp+fn else 0
        f = 2*p*rc/(p+rc) if p+rc else 0
        print(f'{r:<12} {tp:>6} {fp:>6} {fn:>6} {p:>6.3f} {rc:>6.3f} {f:>6.3f}')
        tot_tp += tp; tot_fp += fp; tot_fn += fn
    p = tot_tp/(tot_tp+tot_fp)
    rc = tot_tp/(tot_tp+tot_fn)
    f = 2*p*rc/(p+rc)
    print(f'\nTOTAL: TP={tot_tp} FP={tot_fp} FN={tot_fn}')
    print(f'Precision={p:.3f}  Recall={rc:.3f}  F1={f:.3f}')


if __name__ == '__main__':
    main()
