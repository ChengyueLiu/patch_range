"""Filter out generic/trivial code lines that match everywhere.

Used to avoid false VULN classifications when deleted lines
are too generic (e.g. 'else', 'return 0;', '}').
"""

from __future__ import annotations

import re

# Lines that are pure syntax/control flow - match in any codebase
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

# Normalize before comparison
_TRIVIAL_NORMALIZED = set()
for line in _TRIVIAL_LINES:
    _TRIVIAL_NORMALIZED.add(re.sub(r'\s+', '', line.strip().lower()))


def is_meaningful_line(line: str) -> bool:
    """Check if a code line is meaningful enough for vulnerability matching.

    Returns False for trivial/generic lines that would match anywhere.
    """
    stripped = line.strip()
    if not stripped:
        return False

    # Normalize: remove all whitespace, lowercase
    normalized = re.sub(r'\s+', '', stripped.lower())

    # Check against trivial set
    if normalized in _TRIVIAL_NORMALIZED:
        return False

    # Too short to be meaningful (after stripping)
    if len(stripped) <= 3:
        return False

    return True


def filter_meaningful_lines(lines: list) -> list:
    """Filter a list of code lines to keep only meaningful ones."""
    return [l for l in lines if is_meaningful_line(l)]
