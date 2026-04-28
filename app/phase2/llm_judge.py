"""LLM-based vulnerability judge — Phase 2 Step 2.

Given a fix diff and a target version, ask LLM whether the target version
is vulnerable. The prompt explains the full VARA context so the model
knows exactly what has been done and what it needs to judge.

Evidence preparation uses find_function_body to extract the SPECIFIC function
the fix touches, not a vague ±80 line window.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.git_lib.interface import PatchInfo, FilePatch
from app.git_lib.repo import GitRepo
from app.phase2.llm_tools import find_function_body
from app.phase1.path_resolver import resolve_path


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
# Background

You are part of VARA, a tool that identifies which historical release versions
of an open-source project are affected by a known CVE.

# Our approach

We work in two phases:
- Phase 1 (done): We traced where the patched files were first introduced in
  git history. Every release between file introduction and the fix is a
  candidate. This gives ~93-100% recall but includes false positives.
- Phase 2 Step 1 (done): We used context-aware textual matching to check
  whether the fix's deleted lines exist in each candidate version. This
  resolved ~63% of CVEs exactly. The rest couldn't be determined because:
  (a) the code was refactored (variable/function renamed),
  (b) the code was completely rewritten,
  (c) the fix only ADDED code (no deleted lines to search for), or
  (d) the file was moved to a different path.

# Your task (Phase 2 Step 2)

You receive:
1. The FIX DIFF showing what the fix changed
2. The VULNERABLE FUNCTION extracted from the target version (or a note that
   the function was not found)

Decide: is the target version VULNERABLE or SAFE?

# How to reason

Step 1: Read the fix diff. Identify the ROOT CAUSE — what bug does the fix
address? What dangerous operation was unprotected, or what wrong logic existed?

Step 2: Look at the target version's function body. Ask:
- Does the dangerous operation / vulnerable pattern exist in this code?
- Is the protection that the fix adds ALREADY present (perhaps in a different form)?
- If the function doesn't exist at this version → the code path is absent → SAFE

Step 3: Decide:
- VULN: the dangerous pattern is present AND the protection is absent
- SAFE: either the dangerous pattern doesn't exist, or the protection is present
- UNCLEAR: you cannot determine from the provided code (explain what's missing)

# Common situations with real examples

## Situation 1: Variable/function renamed (code refactored)
CVE-2020-35965 (FFmpeg): Fix changes `for (y = 0; y < s->ymin; y++)` to
`for (y = 0; y < FFMIN(s->ymin, s->h); y++)`. At old version n0.11, the
same loop reads `for (y = 0; y < ymin; y++)` — local variable instead of
struct member, but same semantics: loop bounded by untrusted EXR header
value without capping at image height.
Verdict: VULN — same dangerous pattern under different variable name.

## Situation 2: Add-only fix (no deleted lines)
CVE-2022-1473 (OpenSSL): Fix adds `lh->num_items = 0;` at the end of
`OPENSSL_LH_flush()`. The function frees all entries and NULLs buckets
but forgets to reset the item counter. At OpenSSL_1_1_0, the flush
function exists and lacks this reset.
Verdict: VULN — the dangerous omission (missing counter reset) is present.

CVE-2020-12284 (FFmpeg): Fix adds `if (length > end - start) return
AVERROR_INVALIDDATA;` in `cbs_jpeg_split_fragment()`. At version n2.2,
the file `cbs_jpeg.c` does not exist at all (feature added later).
Verdict: SAFE — the vulnerable code path does not exist yet.

## Situation 3: Code completely rewritten
CVE-2020-12829 (QEMU): Fix replaces hand-written FILL_RECT macro with
pixman calls and adds bounds checking. At v0.13.0, the macro uses
`operation_width`/`operation_height` instead of `width`/`height`, and
`dst_width` instead of `dst_pitch`. But the same dangerous pattern
exists: signed int arithmetic on guest-controlled values used as a
memory index without bounds checking.
Verdict: VULN — same vulnerability pattern despite different variable names.

## Situation 4: Function does not exist at target version
If the function body is reported as "not found", the vulnerable code path
does not exist at this version. In most cases this means SAFE.

# CRITICAL RULES

- Do NOT flag VULN just because the file or function exists. The specific
  dangerous pattern must be present.
- Do NOT flag SAFE just because variable names differ. Refactors are common.
  Check the SEMANTICS.
- If the function is not found at this version → almost always SAFE (the
  feature hasn't been implemented yet).
- If you cannot see enough code to decide → UNCLEAR (never guess).

# Output format

Respond with a single JSON object:
{
  "verdict": "VULN" | "SAFE" | "UNCLEAR",
  "confidence": "high" | "medium" | "low",
  "root_cause": "<one sentence: what is the bug>",
  "reasoning": "<2-4 sentences citing concrete code from the target version>"
}
"""


# ---------------------------------------------------------------------------
# Function name extraction from diff
# ---------------------------------------------------------------------------

_FUNC_DECL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]+)\s*\(")


def _extract_function_names(patch: PatchInfo) -> List[Tuple[str, str]]:
    """Extract (file_path, function_name) pairs from patch hunk headers.

    Returns the most specific function names we can find, ordered by
    hunk header (most reliable) then by diff content.
    """
    results: List[Tuple[str, str]] = []
    seen = set()

    for fp in patch.file_patches:
        path = fp.old_path or fp.new_path
        if not path:
            continue
        for hunk in fp.hunks:
            if hunk.header_context:
                m = _FUNC_DECL_RE.search(hunk.header_context)
                if m:
                    name = m.group(1)
                    key = (path, name)
                    if key not in seen and len(name) >= 4:
                        seen.add(key)
                        results.append(key)

    # Fallback: look for function-like identifiers in deleted/added lines
    if not results:
        for fp in patch.file_patches:
            path = fp.old_path or fp.new_path
            if not path:
                continue
            for hunk in fp.hunks:
                for line in hunk.deleted_lines + hunk.added_lines:
                    m = _FUNC_DECL_RE.search(line)
                    if m:
                        name = m.group(1)
                        if name.lower() not in {"if", "for", "while", "return",
                                                  "sizeof", "switch", "static",
                                                  "struct", "typedef", "extern"}:
                            key = (path, name)
                            if key not in seen and len(name) >= 4:
                                seen.add(key)
                                results.append(key)
            if results:
                break

    return results


# ---------------------------------------------------------------------------
# Diff rendering
# ---------------------------------------------------------------------------

def _render_diff(patch: PatchInfo, max_chars: int = 6000) -> str:
    """Render fix diff in compact unified-diff form, preserving @@ headers."""
    out = []
    for fp in patch.file_patches:
        out.append(f"--- {fp.old_path or '/dev/null'}")
        out.append(f"+++ {fp.new_path or '/dev/null'}")
        for hunk in fp.hunks:
            header = f"@@ ... @@ {hunk.header_context}" if hunk.header_context else "@@"
            out.append(header)
            for ctx in hunk.context_lines[:8]:
                out.append(f" {ctx}")
            for d in hunk.deleted_lines:
                out.append(f"-{d}")
            for a in hunk.added_lines:
                out.append(f"+{a}")
    text = "\n".join(out)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated]"
    return text


# ---------------------------------------------------------------------------
# Evidence preparation — the KEY change: use find_function_body
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    cve_id: str
    repo: str
    target_tag: str
    fix_diff: str
    functions: Dict[str, str]   # "file:function" -> function body or error msg
    notes: str = ""


def build_evidence(
    repo: GitRepo,
    cve_id: str,
    repo_name: str,
    patch: PatchInfo,
    target_tag: str,
) -> Evidence:
    """Build evidence by extracting the SPECIFIC functions the fix touches."""

    fix_diff = _render_diff(patch)
    func_targets = _extract_function_names(patch)
    functions: Dict[str, str] = {}

    for file_path, func_name in func_targets:
        key = f"{file_path}:{func_name}"

        # Try original path first
        body = find_function_body(repo, target_tag, file_path, func_name)

        # If not found, try path resolution
        if body.startswith("[ERROR]") or "not found" in body.lower():
            for fp in patch.file_patches:
                fp_path = fp.old_path or fp.new_path
                if fp_path == file_path:
                    rp = resolve_path(repo, fp, target_tag)
                    if rp.path and rp.path != file_path:
                        body = find_function_body(repo, target_tag, rp.path, func_name)
                        if not body.startswith("[ERROR]") and "not found" not in body.lower():
                            key = f"{rp.path}:{func_name}"
                    break

        functions[key] = body

    # If we found no function names at all, fall back to showing file excerpt
    if not func_targets:
        for fp in patch.file_patches:
            path = fp.old_path or fp.new_path
            if not path:
                continue
            content = repo.find_file_at_version(target_tag, path)
            if content is None:
                rp = resolve_path(repo, fp, target_tag)
                if rp.path:
                    content = repo.find_file_at_version(target_tag, rp.path)
                    path = rp.path
            if content is not None:
                lines = content.splitlines()
                excerpt = lines[:150]
                numbered = [f"{i+1:6d}: {l}" for i, l in enumerate(excerpt)]
                functions[path] = "\n".join(numbered)
            else:
                functions[path] = f"[File does not exist at {target_tag}]"
            break

    return Evidence(
        cve_id=cve_id,
        repo=repo_name,
        target_tag=target_tag,
        fix_diff=fix_diff,
        functions=functions,
    )


# ---------------------------------------------------------------------------
# User message
# ---------------------------------------------------------------------------

def _build_user_message(ev: Evidence) -> str:
    parts = [
        f"CVE: {ev.cve_id}",
        f"Repo: {ev.repo}",
        f"Target version: {ev.target_tag}",
    ]
    parts.append("\n=== FIX DIFF ===")
    parts.append(ev.fix_diff)

    parts.append("\n=== TARGET VERSION CODE ===")
    for key, body in ev.functions.items():
        parts.append(f"\n--- {key} @ {ev.target_tag} ---")
        parts.append(body)

    parts.append("\n=== TASK ===")
    parts.append(
        "Is this target version VULNERABLE or SAFE for this CVE? "
        "Follow the reasoning steps in the system prompt. "
        "Respond with JSON only."
    )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# OpenAI call
# ---------------------------------------------------------------------------

def judge_version(
    ev: Evidence,
    model: str = "gpt-4o-mini",
    api_key: Optional[str] = None,
    timeout: int = 90,
) -> Dict:
    """Call LLM and return parsed verdict dict."""
    try:
        from openai import OpenAI
    except ImportError:
        return {"verdict": "ERROR", "error": "openai not installed"}

    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        return {"verdict": "ERROR", "error": "OPENAI_API_KEY not set"}

    base_url = os.environ.get("OPENAI_BASE_URL") or None
    client = OpenAI(api_key=key, base_url=base_url, timeout=timeout)
    user_msg = _build_user_message(ev)

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
            response_format={"type": "json_object"},
        )
    except Exception as e:
        return {"verdict": "ERROR", "error": str(e)}

    raw = resp.choices[0].message.content or ""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                return {"verdict": "ERROR", "error": "bad JSON", "raw": raw}
        else:
            return {"verdict": "ERROR", "error": "no JSON", "raw": raw}

    parsed["_model"] = model
    parsed["_tokens"] = {
        "prompt": resp.usage.prompt_tokens if resp.usage else None,
        "completion": resp.usage.completion_tokens if resp.usage else None,
    }
    return parsed
