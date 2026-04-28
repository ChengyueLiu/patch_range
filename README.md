# Patch Range — Vulnerability-Affected Version Identification

Given a CVE's fixing commit, predict which release versions of the project
are affected. Two-phase pipeline: high-recall candidate range first
(Phase 1) → precise classification within (Phase 2).

## Project layout

```
.
├── app/                      Core code
│   ├── git_lib/              Git + diff infrastructure
│   ├── phase1/               Candidate range (high recall) + path resolution
│   ├── phase2/               VULN classification (program + LLM)
│   ├── utils.py              Shared utilities (normalize, line filter)
│   └── runner.py             Pipeline orchestrator + statistics
│
├── benchmark/                Ground truth dataset (input)
│   ├── Dataset.json          Original
│   └── Dataset_amended.json  Our corrected version (used by all scripts)
│
├── data/
│   ├── repos/                Git clones of analyzed projects (gitignored, ~12GB)
│   ├── cache/                git tag --contains cache (gitignored)
│   ├── runs/                 Pipeline outputs, one dir per run (gitignored)
│   └── analysis/             Exploratory analysis outputs (gitignored)
│
├── analysis/                 Exploratory analysis scripts (one-off tools)
├── docs/                     Documentation
│   ├── approach.md             methodology
│   ├── case_analysis/          per-class case studies
│   └── reference/              external reference materials
│
├── run_program.py            ENTRY: run program-only pipeline (no LLM)
├── run_llm.py                ENTRY: run with LLM phase 2 step 2
└── report.py                 ENTRY: compute F1 / precision / recall
```

## Workflow

```bash
# Run program-only pipeline on full benchmark
python run_program.py --name baseline_v1
# → data/runs/baseline_v1/results.jsonl

# Run with LLM (requires OPENAI_API_KEY in .env)
python run_llm.py --name llm_v1 --model gpt-4o-mini

# Run on subset for quick iteration
python run_llm.py --limit 20 --name quick_test
python run_llm.py --cve CVE-2020-12284            # single CVE → stdout

# Compute metrics
python report.py data/runs/llm_v1                 # F1 + per-repo + per-case
python report.py data/runs/llm_v1 --show errors   # also list EARLY/SAFE
python report.py --latest                         # latest run

# Compare two runs
python report.py --compare data/runs/v1 data/runs/v2
```

Each `run_*.py` invocation creates a new `data/runs/<name>/` directory
with `results.jsonl` + `config.json`. Re-running with the same `--name`
errors (won't overwrite) — pick a new name or omit for a timestamp.

## Pipeline phases

1. **Phase 1** (`app/phase1/candidate_range.py`):
   trace each patched file to its introduction commit (across all branches,
   including cross-file migrations), then take the union of `git tag --contains`.
   Achieves 93–100% recall.
2. **Phase 1.5** (`app/phase1/path_resolver.py`):
   resolve the patched file's actual path at each target tag (handles
   renames/moves). Closes a recall gap before Phase 2 reads code.
3. **Phase 2 Step 1** (`app/phase2/classifier.py`):
   context-aware deleted-line matching. Classifies each candidate version
   as VULN or UNCLEAR using the patch's hunk context to locate the right
   region.
4. **Phase 2 Step 2** (`app/phase2/llm_judge.py` + `state_dedup.py` +
   `llm_tools.py`):
   group UNCLEAR tags by code hash, then binary-search on the unique
   states using GPT to judge each.

## Setup

```bash
pip install openai tqdm
echo "OPENAI_API_KEY=sk-..." > .env
```

The benchmark expects clones in `data/repos/<project>` (FFmpeg, ImageMagick,
curl, httpd, openjpeg, openssl, qemu, wireshark).
