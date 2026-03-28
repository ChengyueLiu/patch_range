"""Data types for evaluation framework."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set, Iterator, Callable


# ============================================================
# Tool interface
# ============================================================

# A tool is simply a callable: (repo_path, commits) -> affected_versions
ToolCallable = Callable[[str, List[str]], List[str]]


# ============================================================
# Configuration
# ============================================================

@dataclass
class EvaluationConfig:
    """Configuration for running an evaluation."""
    dataset_path: str
    repos_dir: str
    output_dir: str
    timeout_per_cve: int = 300
    max_cves: int = 0  # 0 means no limit
    num_workers: int = 1  # number of parallel workers


# ============================================================
# Dataset
# ============================================================

@dataclass
class CVEEntry:
    """A single CVE from the benchmark dataset."""
    cve_id: str
    repo: str
    fixing_commits: List[List[str]]
    affected_versions: List[str]
    cwe: List[str] = field(default_factory=list)

    @property
    def all_commits(self) -> List[str]:
        return [c for group in self.fixing_commits for c in group]


@dataclass
class Dataset:
    """The full benchmark dataset."""
    entries: Dict[str, CVEEntry] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[CVEEntry]:
        return iter(self.entries.values())

    def repos(self) -> Set[str]:
        return {e.repo for e in self.entries.values()}

    @staticmethod
    def load(path: str) -> Dataset:
        with open(path) as f:
            raw = json.load(f)
        entries = {}
        for cve_id, entry in raw.items():
            entries[cve_id] = CVEEntry(
                cve_id=cve_id,
                repo=entry["repo"],
                fixing_commits=entry["fixing_commits"],
                affected_versions=entry["affected_version"],
                cwe=entry.get("CWE", []),
            )
        return Dataset(entries=entries)


# ============================================================
# Tool result
# ============================================================

@dataclass
class ToolResult:
    """Result of running the tool on a single CVE."""
    cve_id: str
    status: str  # success / error / timeout
    predicted_versions: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    error_message: str = ""


# ============================================================
# Comparison
# ============================================================

@dataclass
class ComparisonResult:
    """Comparison of predicted vs ground truth for a single CVE."""
    cve_id: str
    repo: str
    cwe: List[str]
    status: str
    predicted: List[str]
    ground_truth: List[str]
    tp: List[str] = field(default_factory=list)
    fp: List[str] = field(default_factory=list)
    fn: List[str] = field(default_factory=list)

    @property
    def exact_match(self) -> bool:
        return set(self.predicted) == set(self.ground_truth)

    @property
    def no_miss(self) -> bool:
        return len(self.fn) == 0


# ============================================================
# Metrics
# ============================================================

@dataclass
class VersionMetrics:
    """Version-level metrics."""
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class VulnMetrics:
    """Vulnerability-level metrics."""
    total: int = 0
    exact_match: int = 0
    no_miss: int = 0
    success: int = 0

    @property
    def accuracy(self) -> float:
        return self.exact_match / self.total if self.total > 0 else 0.0

    @property
    def no_miss_ratio(self) -> float:
        return self.no_miss / self.total if self.total > 0 else 0.0
