# Analysis Scripts

Ad-hoc, one-off scripts used to investigate specific failures or validate
parts of the pipeline. Not part of the regular evaluation flow — those are
`run_program.py`, `run_llm.py`, `report.py` at the project root.

## Scripts

- `audit_step1_early.py` — for every Step-1 EARLY case, compare the code
  at our predicted `our_earliest` vs the GT `gt_earliest`. Used to
  identify cases where GT is too narrow vs cases where Step 1 has a real
  false positive.

- `analyze_early_cause.py` — categorize EARLY cases (from a previous
  llm_phase2 run) into "Step 1 caused" vs "LLM caused" failure modes.

- `top_fp.py` — list the CVEs producing the most tag-level false
  positives (sorted descending). Quickly find the biggest precision
  problems.

- `eval_path_resolver.py` — sanity check Phase 1.5 path resolution on
  the 20 file_not_found cases from a prior analysis. Useful when changing
  resolver heuristics.

These scripts read from `data/runs/<name>/results.jsonl` or
`data/analysis/`. Outputs (when written) go to `data/analysis/`.
