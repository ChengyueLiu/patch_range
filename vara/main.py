"""VARA CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys

from vara.analyzer import analyze


def main():
    parser = argparse.ArgumentParser(description="VARA: Vulnerability Affected Range Analyzer")
    parser.add_argument("--repo", required=True, help="Path to the git repository")
    parser.add_argument("--commit", required=True, action="append", dest="commits",
                        help="Fixing commit hash (can be specified multiple times)")
    args = parser.parse_args()

    affected = analyze(args.repo, args.commits)
    json.dump(affected, sys.stdout)


if __name__ == "__main__":
    main()
