"""Pre-filter tags to keep only formal release versions.

Removes dev, rc, beta, alpha, pre-release, internal, and other non-release tags.
This reduces both runtime (fewer tags to check) and false positives.
"""

from __future__ import annotations

import re
from typing import List


# Case-insensitive patterns
_CI_PATTERNS = [
    # Dev / pre-release / release candidate
    r'[-.](?:dev|rc\d*|alpha\d*|beta\d*|pre\d*)(?:\b|$)',
    r'-candidate$',
    # Internal / build tags
    r'clang.format',
    r'^(before_|after_|pre_|post_)',
    r'^backups/',
    r'^(initial|start|staging|trivial)',
    # Pull request / branch merge markers
    r'pull.request',
    r'_merge$',
    # Old-style release_ tags
    r'^release[-_]',
    # Ethereal (old wireshark name)
    r'^ethereal-',
    # Tags with @ (backup refs)
    r'@',
    # tiny-curl variant tags
    r'^tiny-',
    # Misc non-version tags (openjpeg)
    r'^(arelease|opj\d|wg\d)$',
    # curl internal milestone tags
    r'^curl-.*-pre',
    # OpenSSL-engine tags
    r'^openssl-engine-',
]

# Case-sensitive patterns (need exact case matching)
_CS_PATTERNS = [
    # Random single-letter tags like 'N'
    r'^[A-Z]$',
    # ALL_CAPS internal tags (e.g. BEN_FIPS_TEST_*, FIPS_098_TEST_*, BEFORE_COMPAQ_PATCH)
    # but NOT OpenSSL_1_0_2 style (mixed case with digits)
    r'^[A-Z][A-Z0-9]*_[A-Z0-9]+_[A-Z]',
]

_CI_RE = re.compile('|'.join(f'({p})' for p in _CI_PATTERNS), re.IGNORECASE)
_CS_RE = re.compile('|'.join(f'({p})' for p in _CS_PATTERNS))


def is_release_tag(tag: str) -> bool:
    """Check if a tag looks like a formal release version."""
    if _CI_RE.search(tag):
        return False
    if _CS_RE.search(tag):
        return False
    return True


def filter_release_tags(tags: List[str]) -> List[str]:
    """Filter a list of tags to keep only formal release versions."""
    return [t for t in tags if is_release_tag(t)]
