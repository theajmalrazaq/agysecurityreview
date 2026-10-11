#!/usr/bin/env python3
"""Inspect git status, branch changes, and commit range for security review."""

from __future__ import annotations

import json
import subprocess
import sys


def run_git(args: list[str], cwd: str | None = None) -> tuple[int, str]:
    try:
        res = subprocess.run(
            ["git", "-C", cwd or "."] + args,
            capture_output=True,
            text=True,
            check=False,
            env={"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"},
        )
        return res.returncode, res.stdout.strip()
    except Exception as e:
        return 1, str(e)


def get_git_info(cwd: str | None = None) -> dict:
    code, status = run_git(["status", "-sb", "--untracked-files=all"], cwd)
    if code != 0:
        return {"is_git": False, "error": "Not a git repository"}

    lines = status.splitlines()
    branch_line = lines[0] if lines else ""
    uncommitted = lines[1:] if len(lines) > 1 else []

    # Resolve base branch
    base_ref = None
    for candidate in ["origin/main", "origin/master", "main", "master", "HEAD~1"]:
        c_code, _ = run_git(["rev-parse", "--verify", "--quiet", candidate], cwd)
        if c_code == 0:
            base_ref = candidate
            break

    code_head, head_sha = run_git(["rev-parse", "HEAD"], cwd)

    # Check diff against base
    diff_stat = ""
    changed_files = []
    if base_ref:
        _, merge_base = run_git(["merge-base", base_ref, "HEAD"], cwd)
        if merge_base and merge_base != head_sha:
            _, diff_stat = run_git(["diff", "--numstat", f"{merge_base}..HEAD"], cwd)
            _, files_str = run_git(["diff", "--name-only", f"{merge_base}..HEAD"], cwd)
            changed_files = [f for f in files_str.splitlines() if f.strip()]

    # If no branch diff, check working tree diff
    if not changed_files and uncommitted:
        _, diff_stat = run_git(["diff", "--numstat", "HEAD"], cwd)
        _, files_str = run_git(["diff", "--name-only", "HEAD"], cwd)
        changed_files = [f for f in files_str.splitlines() if f.strip()]

    return {
        "is_git": True,
        "branch_summary": branch_line,
        "head_sha": head_sha if code_head == 0 else "",
        "base_ref": base_ref or "",
        "uncommitted_count": len(uncommitted),
        "changed_files": changed_files,
        "diff_stat": diff_stat,
    }


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    info = get_git_info(path)
    print(json.dumps(info, indent=2))
