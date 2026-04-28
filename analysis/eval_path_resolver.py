"""Run path resolver on all 20 file_not_found cases.

For each case, resolve the path and validate by checking whether the resolved
file at the GT tag contains a non-trivial fraction of the patch's identifiers.
"""

import json
import sys
from collections import Counter

from app.git_lib.repo import GitRepo
from app.git_lib.patch_parser import parse_commits
from app.phase1.path_resolver import resolve_path
from app.utils import is_meaningful_line
from app.phase2.classifier import classify_file_version


def main():
    analysis = json.load(open("data/analysis/phase2_analysis.json"))
    dataset = json.load(open("benchmark/Dataset_amended.json"))

    cases = []
    for r in analysis:
        if r["category"] != "SAFE":
            continue
        if r["gt_analysis"]["file_exists"]:
            continue
        cases.append(r)

    print(f"Total file_not_found cases: {len(cases)}\n")
    print(f"{'CVE':<22} {'Repo':<11} {'GT':<24} {'Patch path':<40} {'Resolved':<40} {'Conf':<10} {'Class'}")
    print("-" * 170)

    bucket = Counter()
    for r in cases:
        cve = r["cve"]
        repo_name = r["repo"]
        gt_tag = r["gt_tag"]
        e = dataset[cve]
        repo = GitRepo(f"data/repos/{repo_name}")
        commits = [c for g in e["fixing_commits"] for c in g]
        patch = parse_commits(repo, commits)
        if not patch.file_patches:
            print(f"{cve:<22} {repo_name:<11} {gt_tag:<24} (no patch)")
            bucket["no_patch"] += 1
            continue

        # Try resolving the FIRST patch file
        fp = patch.file_patches[0]
        target = fp.old_path or fp.new_path
        rp = resolve_path(repo, fp, gt_tag)

        # If resolved, run classifier on resolved file to see if VULN signal recovers
        cls = "-"
        if rp.path:
            content = repo.find_file_at_version(gt_tag, rp.path)
            if content is not None:
                vc, matched, total = classify_file_version(content, fp)
                cls = f"{vc}({matched}/{total})"

        bucket[rp.confidence] += 1
        print(f"{cve:<22} {repo_name:<11} {gt_tag:<24} {target[:38]:<40} {(rp.path or '-')[:38]:<40} {rp.confidence:<10} {cls}")

    print("-" * 170)
    print(f"\nResolution buckets: {dict(bucket)}")


if __name__ == "__main__":
    main()
