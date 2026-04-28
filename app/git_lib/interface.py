"""Data types for VARA tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HunkChange:
    """A single hunk within a file diff."""
    deleted_lines: List[str] = field(default_factory=list)
    added_lines: List[str] = field(default_factory=list)
    context_lines: List[str] = field(default_factory=list)
    # Text after the second `@@` on the hunk header line (typically a function
    # signature like `static int decode_frame(...)`). Empty string if absent.
    header_context: str = ""


@dataclass
class FilePatch:
    """All changes to a single file in a commit."""
    old_path: Optional[str]
    new_path: Optional[str]
    hunks: List[HunkChange] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.old_path or self.new_path

    @property
    def all_deleted_lines(self) -> List[str]:
        return [line for hunk in self.hunks for line in hunk.deleted_lines]

    @property
    def all_added_lines(self) -> List[str]:
        return [line for hunk in self.hunks for line in hunk.added_lines]


@dataclass
class PatchInfo:
    """Parsed patch from one or more fixing commits."""
    commit_hashes: List[str]
    file_patches: List[FilePatch] = field(default_factory=list)


@dataclass
class FileMatchResult:
    """Match result for a single file in a single version."""
    file_path: str
    found: bool
    vulnerable_lines_matched: int
    vulnerable_lines_total: int
    fix_lines_absent: int
    fix_lines_total: int


@dataclass
class VersionResult:
    """Aggregated match result for a single version."""
    version: str
    is_affected: bool
    file_results: List[FileMatchResult] = field(default_factory=list)
