"""Evaluator: runs a tool on the benchmark, compares, and computes metrics."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from tqdm import tqdm

from evaluation.interface import (
    EvaluationConfig, Dataset, CVEEntry, ToolCallable,
    ToolResult, ComparisonResult, VersionMetrics, VulnMetrics,
)


def _worker(args: Tuple) -> ToolResult:
    """Worker function for parallel execution. Must be top-level for pickling."""
    tool, repo_path, commits, cve_id = args
    start_time = time.time()
    try:
        predicted = tool(repo_path, commits)
        return ToolResult(
            cve_id=cve_id, status="success",
            predicted_versions=predicted,
            elapsed_seconds=time.time() - start_time,
        )
    except Exception as e:
        return ToolResult(
            cve_id=cve_id, status="error",
            elapsed_seconds=time.time() - start_time,
            error_message=str(e),
        )


class Evaluator:
    """Evaluates a vulnerability-affected version identification tool."""

    def __init__(self, config: EvaluationConfig, tool: ToolCallable):
        self.config = config
        self.tool = tool
        self.dataset = Dataset.load(config.dataset_path)
        self.repos_dir = Path(config.repos_dir)
        self.output_dir = Path(config.output_dir)

        self.results: Dict[str, ToolResult] = {}
        self.comparisons: Dict[str, ComparisonResult] = {}

    # ---- Step 1: Run tool ----

    def run(self) -> str:
        """Run tool on all CVEs and save results. Returns the run directory path."""
        run_dir = self._create_run_dir()
        limit = self.config.max_cves
        num_workers = self.config.num_workers

        # Collect entries to run
        entries = []
        for entry in self.dataset:
            if 0 < limit <= len(entries):
                break
            entries.append(entry)

        total = len(entries)

        # Build worker args
        worker_args = [
            (self.tool, str(self.repos_dir / e.repo), e.all_commits, e.cve_id)
            for e in entries
        ]

        pbar = tqdm(total=total, desc="Running tool", unit="CVE")

        if num_workers <= 1:
            for entry, args in zip(entries, worker_args):
                result = _worker(args)
                self.results[result.cve_id] = result
                pbar.set_postfix_str(f"{entry.cve_id} {result.status} {result.elapsed_seconds:.1f}s")
                pbar.update(1)
        else:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(_worker, args): entry
                    for entry, args in zip(entries, worker_args)
                }
                for future in as_completed(futures):
                    result = future.result()
                    entry = futures[future]
                    self.results[result.cve_id] = result
                    pbar.set_postfix_str(f"{entry.cve_id} {result.status} {result.elapsed_seconds:.1f}s")
                    pbar.update(1)

        pbar.close()

        self._save_json(run_dir / "results.json", self._results_to_dict())

        statuses = defaultdict(int)
        for r in self.results.values():
            statuses[r.status] += 1
        print(f"\nDone. {dict(statuses)}")
        print(f"Results saved to {run_dir / 'results.json'}")
        return str(run_dir)

    # ---- Step 2: Compare ----

    def compare(self, results_path: str) -> str:
        """Compare results with ground truth. Returns the comparison file path."""
        self._load_results(results_path)
        run_dir = Path(results_path).parent

        for entry in self.dataset:
            if entry.cve_id not in self.results:
                continue
            result = self.results[entry.cve_id]
            pred_set = set(result.predicted_versions)
            gt_set = set(entry.affected_versions)

            self.comparisons[entry.cve_id] = ComparisonResult(
                cve_id=entry.cve_id,
                repo=entry.repo,
                cwe=entry.cwe,
                status=result.status,
                predicted=sorted(result.predicted_versions),
                ground_truth=sorted(entry.affected_versions),
                tp=sorted(pred_set & gt_set),
                fp=sorted(pred_set - gt_set),
                fn=sorted(gt_set - pred_set),
            )

        out_path = run_dir / "comparison.json"
        self._save_json(out_path, self._comparisons_to_dict())
        print(f"Comparison saved to {out_path} ({len(self.comparisons)} CVEs)")
        return str(out_path)

    # ---- Step 3: Metrics ----

    def metrics(self, comparison_path: str) -> str:
        """Compute metrics from comparison results. Returns the metrics file path."""
        self._load_comparisons(comparison_path)
        run_dir = Path(comparison_path).parent

        overall_vuln = VulnMetrics()
        overall_ver = VersionMetrics()
        repo_vuln: Dict[str, VulnMetrics] = defaultdict(VulnMetrics)
        repo_ver: Dict[str, VersionMetrics] = defaultdict(VersionMetrics)

        for comp in self.comparisons.values():
            overall_vuln.total += 1
            if comp.status == "success":
                overall_vuln.success += 1
            if comp.exact_match:
                overall_vuln.exact_match += 1
            if comp.no_miss:
                overall_vuln.no_miss += 1

            tp, fp, fn = len(comp.tp), len(comp.fp), len(comp.fn)
            overall_ver.tp += tp
            overall_ver.fp += fp
            overall_ver.fn += fn

            r = comp.repo
            repo_vuln[r].total += 1
            repo_vuln[r].success += int(comp.status == "success")
            repo_vuln[r].exact_match += int(comp.exact_match)
            repo_vuln[r].no_miss += int(comp.no_miss)
            repo_ver[r].tp += tp
            repo_ver[r].fp += fp
            repo_ver[r].fn += fn

        report = {
            "overall": self._metrics_dict(overall_vuln, overall_ver),
            "per_repo": {
                r: self._metrics_dict(repo_vuln[r], repo_ver[r])
                for r in sorted(repo_vuln)
            },
        }

        out_path = run_dir / "metrics.json"
        self._save_json(out_path, report)
        self._print_report(report)
        print(f"\nFull report saved to {out_path}")
        return str(out_path)

    # ---- Convenience: run all 3 steps ----

    def run_all(self):
        """Run all three steps sequentially."""
        run_dir = self.run()
        results_path = str(Path(run_dir) / "results.json")
        comparison_path = self.compare(results_path)
        self.metrics(comparison_path)

    # ---- IO helpers ----

    def _create_run_dir(self) -> Path:
        now = datetime.now()
        run_dir = self.output_dir / now.strftime("%Y%m") / now.strftime("%d") / now.strftime("%H%M%S")
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _load_results(self, path: str):
        with open(path) as f:
            raw = json.load(f)
        self.results = {}
        for cve_id, r in raw.items():
            self.results[cve_id] = ToolResult(
                cve_id=cve_id,
                status=r["status"],
                predicted_versions=r.get("predicted_versions", []),
                elapsed_seconds=r.get("elapsed_seconds", 0.0),
                error_message=r.get("error_message", ""),
            )

    def _load_comparisons(self, path: str):
        with open(path) as f:
            raw = json.load(f)
        self.comparisons = {}
        for cve_id, c in raw.items():
            self.comparisons[cve_id] = ComparisonResult(
                cve_id=cve_id,
                repo=c["repo"],
                cwe=c["cwe"],
                status=c["status"],
                predicted=c["predicted"],
                ground_truth=c["ground_truth"],
                tp=c["tp"],
                fp=c["fp"],
                fn=c["fn"],
            )

    def _results_to_dict(self) -> dict:
        return {
            cve_id: {
                "status": r.status,
                "predicted_versions": r.predicted_versions,
                "elapsed_seconds": r.elapsed_seconds,
                "error_message": r.error_message,
            }
            for cve_id, r in self.results.items()
        }

    def _comparisons_to_dict(self) -> dict:
        return {
            cve_id: {
                "repo": c.repo, "cwe": c.cwe, "status": c.status,
                "predicted": c.predicted, "ground_truth": c.ground_truth,
                "tp": c.tp, "fp": c.fp, "fn": c.fn,
                "exact_match": c.exact_match, "no_miss": c.no_miss,
            }
            for cve_id, c in self.comparisons.items()
        }

    @staticmethod
    def _save_json(path: Path, data: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _metrics_dict(vm: VulnMetrics, vr: VersionMetrics) -> dict:
        return {
            "vulnerability_level": {
                "accuracy": round(vm.accuracy, 4),
                "no_miss_ratio": round(vm.no_miss_ratio, 4),
                "total": vm.total, "exact_match": vm.exact_match,
                "no_miss": vm.no_miss, "success": vm.success,
            },
            "version_level": {
                "precision": round(vr.precision, 4),
                "recall": round(vr.recall, 4),
                "f1": round(vr.f1, 4),
                "tp": vr.tp, "fp": vr.fp, "fn": vr.fn,
            },
        }

    @staticmethod
    def _print_report(report: dict):
        vl = report["overall"]["vulnerability_level"]
        vr = report["overall"]["version_level"]
        print("\n" + "=" * 60)
        print("EVALUATION RESULTS")
        print("=" * 60)
        print(f"\nVulnerability-level ({vl['total']} CVEs, {vl['success']} succeeded):")
        print(f"  Accuracy:       {vl['accuracy']:.2%}  ({vl['exact_match']}/{vl['total']})")
        print(f"  No-Miss Ratio:  {vl['no_miss_ratio']:.2%}  ({vl['no_miss']}/{vl['total']})")
        print(f"\nVersion-level:")
        print(f"  Precision: {vr['precision']:.2%}")
        print(f"  Recall:    {vr['recall']:.2%}")
        print(f"  F1:        {vr['f1']:.2%}")
        print(f"\nPer-repo breakdown:")
        print(f"  {'Repo':<15} {'#CVE':>5} {'Acc':>7} {'NMR':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
        print(f"  {'-'*15} {'-'*5} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
        for repo, m in report["per_repo"].items():
            vl_m, vr_m = m["vulnerability_level"], m["version_level"]
            print(f"  {repo:<15} {vl_m['total']:>5} {vl_m['accuracy']:>6.2%} "
                  f"{vl_m['no_miss_ratio']:>6.2%} {vr_m['precision']:>6.2%} "
                  f"{vr_m['recall']:>6.2%} {vr_m['f1']:>6.2%}")
