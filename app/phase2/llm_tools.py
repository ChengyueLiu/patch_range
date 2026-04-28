"""Deterministic tools available to the online LLM agent.

These are the bounded set of operations the agent can request during online
verification. Each returns a string suitable for injection into a chat message.

The agent cannot run arbitrary git commands — only these four tools.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional, Tuple

from app.git_lib.repo import GitRepo


def read_file_excerpt(
    repo: GitRepo,
    tag: str,
    file_path: str,
    start_line: int = 1,
    num_lines: int = 120,
) -> str:
    """Read a slice of a file at a specific tag, with line numbers.

    Returns a numbered-source-code string, or an error message.
    """
    content = repo.find_file_at_version(tag, file_path)
    if content is None:
        return f"[ERROR] File '{file_path}' does not exist at tag '{tag}'."
    lines = content.splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), start + num_lines)
    numbered = [f"{i+1:6d}: {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


def grep_at_tag(
    repo: GitRepo,
    tag: str,
    pattern: str,
    max_results: int = 15,
) -> str:
    """Search for a literal string across all files at a tag.

    Returns file:lineno:line hits, or a "no matches" message.
    """
    if len(pattern) < 4:
        return "[ERROR] Pattern too short (min 4 chars)."
    try:
        out = subprocess.run(
            ["git", "grep", "-n", "-F", "--", pattern, tag, "--"],
            cwd=str(repo.path),
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception as e:
        return f"[ERROR] git grep failed: {e}"
    if not out.strip():
        return f"No matches for '{pattern}' at {tag}."
    lines = out.strip().splitlines()
    # Strip the tag: prefix from each line
    cleaned = []
    for line in lines[:max_results]:
        if ":" in line:
            cleaned.append(line.split(":", 1)[1])
        else:
            cleaned.append(line)
    suffix = f"\n... ({len(lines) - max_results} more)" if len(lines) > max_results else ""
    return "\n".join(cleaned) + suffix


def list_dir_at_tag(
    repo: GitRepo,
    tag: str,
    directory: str = "",
    max_entries: int = 60,
) -> str:
    """List files/directories at a path in the tag's tree.

    Returns one entry per line, or an error message.
    """
    try:
        out = subprocess.run(
            ["git", "ls-tree", "--name-only", tag, directory + "/" if directory else ""],
            cwd=str(repo.path),
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception as e:
        return f"[ERROR] ls-tree failed: {e}"
    if not out.strip():
        return f"Directory '{directory}' is empty or does not exist at {tag}."
    entries = out.strip().splitlines()
    suffix = f"\n... ({len(entries) - max_entries} more)" if len(entries) > max_entries else ""
    return "\n".join(entries[:max_entries]) + suffix


def find_function_body(
    repo: GitRepo,
    tag: str,
    file_path: str,
    function_name: str,
    context_before: int = 3,
    max_lines: int = 100,
) -> str:
    """Find and return the body of a C function in a file at a tag.

    Uses a simple brace-counting heuristic that works for most C code.
    Returns the function body with line numbers, or an error message.
    """
    content = repo.find_file_at_version(tag, file_path)
    if content is None:
        return f"[ERROR] File '{file_path}' does not exist at tag '{tag}'."
    lines = content.splitlines()

    # Find the function declaration line
    func_re = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    start_idx = None
    for i, line in enumerate(lines):
        if func_re.search(line):
            # Heuristic: skip forward declarations (lines ending with ;)
            rest = "".join(lines[i:i+5])
            check = rest.split("{")[0] if "{" in rest else rest
            if ";" in check:
                continue
            start_idx = i
            break

    if start_idx is None:
        return f"Function '{function_name}' not found in '{file_path}' at {tag}."

    # Walk forward counting braces to find end of function
    brace_depth = 0
    found_open = False
    end_idx = start_idx
    for i in range(start_idx, min(len(lines), start_idx + 500)):
        line = lines[i]
        # Strip string literals and comments for brace counting
        stripped = re.sub(r'"[^"]*"', '', line)
        stripped = re.sub(r"'[^']*'", '', stripped)
        stripped = re.sub(r'//.*$', '', stripped)
        for ch in stripped:
            if ch == '{':
                brace_depth += 1
                found_open = True
            elif ch == '}':
                brace_depth -= 1
        end_idx = i
        if found_open and brace_depth <= 0:
            break

    out_start = max(0, start_idx - context_before)
    out_end = min(len(lines), end_idx + 2)

    if out_end - out_start > max_lines:
        out_end = out_start + max_lines

    numbered = [f"{i+1:6d}: {lines[i]}" for i in range(out_start, out_end)]
    return "\n".join(numbered)


# Tool schema for OpenAI tool-calling (function definitions)
AGENT_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "read_file_excerpt",
            "description": "Read lines from a file at the target version. Use this to examine code around a specific location.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path of the file in the repository"},
                    "start_line": {"type": "integer", "description": "First line to read (1-based)", "default": 1},
                    "num_lines": {"type": "integer", "description": "Number of lines to read", "default": 120},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_at_tag",
            "description": "Search for a literal string across all files at the target version. Use this to locate functions, variables, or code patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Literal string to search for (min 4 chars)"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir_at_tag",
            "description": "List files and directories at a path in the target version's source tree.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory path (empty string for root)", "default": ""},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_function_body",
            "description": "Find and return the body of a C/C++ function in a file at the target version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path of the file"},
                    "function_name": {"type": "string", "description": "Name of the function to find"},
                },
                "required": ["file_path", "function_name"],
            },
        },
    },
]
