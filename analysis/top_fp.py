"""Find CVEs producing the most FP."""
import json
from concurrent.futures import ProcessPoolExecutor
from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.git_lib.tag_filter import filter_release_tags
from app.phase1.candidate_range import layer1


def process(args):
    cve_id, entry, our_e = args
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
        if our_e and our_e != '-':
            our_idx = tag_order.get(our_e, 10 ** 9)
            our_set = {t for t in candidates if tag_order.get(t, 10 ** 9) >= our_idx}
        else:
            our_set = set()
        gt_in = gt & release_set
        tp = len(our_set & gt_in)
        fp = len(our_set - gt_in)
        fn = len(gt_in - our_set)
        gt_earliest = sorted(gt_in, key=lambda t: tag_order.get(t, 10 ** 9))[0] if gt_in else '-'
        return (cve_id, entry['repo'], tp, fp, fn, our_e, gt_earliest)
    except Exception:
        return None


def main():
    dataset = json.load(open('benchmark/Dataset_amended.json'))
    llm = {
        r['cve']: r.get('our_earliest')
        for r in [json.loads(l) for l in open('data/runs/legacy_llm_phase2/results.jsonl') if l.strip()]
    }
    repos = ['FFmpeg', 'ImageMagick', 'curl', 'httpd', 'openjpeg', 'openssl', 'qemu', 'wireshark']
    args = [(cid, e, llm.get(cid)) for cid, e in dataset.items()
            if e.get('repo') in repos and cid in llm]

    per_cve = []
    with ProcessPoolExecutor(max_workers=12) as ex:
        for r in ex.map(process, args):
            if r:
                per_cve.append(r)

    per_cve.sort(key=lambda x: -x[3])
    print("Top 20 FP offenders:")
    print(f"{'CVE':<22} {'Repo':<10} {'TP':>5} {'FP':>6} {'FN':>4} {'Our':>18} {'GT':>18}")
    for r in per_cve[:20]:
        print(f"{r[0]:<22} {r[1]:<10} {r[2]:>5} {r[3]:>6} {r[4]:>4} {str(r[5] or '-'):>18} {str(r[6]):>18}")


if __name__ == '__main__':
    main()
