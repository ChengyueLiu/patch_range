"""Shared utilities used across the pipeline.

- `normalize(line)` — canonical form of a code line for textual comparison
  (whitespace collapsed, operator spacing removed). Used by classifier,
  state-dedup, path resolver, etc.

- `is_meaningful_line(line)` — filter out generic/trivial code lines
  ("}", "else", "return 0;", goto labels, etc.) that would otherwise
  cause false VULN matches in unrelated code.
"""

from __future__ import annotations

import re
from typing import List


# ---------------------------------------------------------------------------
# Code line normalization
# ---------------------------------------------------------------------------

def normalize(line: str) -> str:
    """Canonical form of a code line for comparison.

    Strips whitespace, collapses internal whitespace runs, and removes
    spaces around common C operators so that minor formatting differences
    don't break exact-string matching.
    """
    s = line.strip()
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'\s*([*/%+\-&|^=<>!,;(){}[\]])\s*', r'\1', s)
    return s


# ---------------------------------------------------------------------------
# Trivial-line filter
# ---------------------------------------------------------------------------

_TRIVIAL_LINES = {
    '{', '}', '};', '},', ');', '),', '],', '{}',
    'else', 'else {', '} else {', '} else',
    'break;', 'continue;', 'return;',
    'return 0;', 'return 1;', 'return -1;', 'return -2;',
    'return NULL;', 'return(0);', 'return(1);',
    'default:', 'do {', 'for(;;) {', 'for (;;) {', 'while(1) {',
    'struct {', 'enum {', 'union {',
    '#else', '#endif', '#if', '#ifdef', '#ifndef', '#undef', 'endif',
    'static', 'static int', 'void', 'int', 'double', 'ssize_t',
    'NULL);', 'NULL,', '0,', '0)',
    'err:', 'out:', 'fail:', 'done:', 'exit:', 'end:', 'retry:', 'bail:',
    'next:', 'cleanup:', 'unlock:', 'found:', 'start:',
    'goto err;', 'goto out;', 'goto fail;', 'goto done;',
    'goto exit;', 'goto end;', 'goto bail;', 'goto next;',
    'goto cleanup;', 'goto retry;', 'goto found;',
    'i++;', 'j++;', 'n++;', 'count++;', 'len++;', 'size++;',
    'i = 0;', 'ret = 0;', 'err = 0;', 'rc = 0;', 'len = 0;',
    'ret = -1;', 'rc = -1;',
    'int i;', 'int j;', 'int err;', 'int ret;', 'int rc;', 'int rv;',
    'int len;', 'int n;', 'int i, j;', 'int count;', 'int flags;',
    'int size;', 'int off;', 'int pos;',
    'char *p;', 'char *buf;',
    'free(buf);', 'free(p);',
    'close(fd);',
}

_TRIVIAL_NORMALIZED = {
    re.sub(r'\s+', '', line.strip().lower()) for line in _TRIVIAL_LINES
}


def is_meaningful_line(line: str) -> bool:
    """True if `line` carries enough specificity for vulnerability matching.

    Returns False for trivial/generic lines that would match arbitrary code.
    """
    stripped = line.strip()
    if not stripped:
        return False
    normalized = re.sub(r'\s+', '', stripped.lower())
    if normalized in _TRIVIAL_NORMALIZED:
        return False
    if len(stripped) <= 3:
        return False
    return True


def filter_meaningful_lines(lines: List[str]) -> List[str]:
    return [l for l in lines if is_meaningful_line(l)]
