#!/usr/bin/env python3
"""Classify a git diff into UI hot-patch vs image rebuild actions."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

RUNNER_REBUILD_GLOBS = [
    "scanners/runner/**",
    "scanners/**",
    "scripts/**",
    "web/**",
    "config/**",
    "requirements.txt",
    "requirements*.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "scanners/runner/requirements.txt",
]

UI_REBUILD_GLOBS = [
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose*.yml",
    "compose.yml",
    "compose*.yml",
    "requirements.txt",
    "requirements*.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
]

UI_HOTPATCH_GLOBS = [
    "web/**",
    "scanners/**",
    "scripts/**",
    "config/**",
]

IGNORE_GLOBS = [
    "docs/**",
    "README.md",
    ".cursor/**",
    "tests/**",
    "infra/**",
    ".github/**",
    ".githooks/**",
    "*.md",
    ".gitignore",
    ".env*",
    "**/*.xlsx",
    "**/*.pptx",
    "**/*.pdf",
    "**/*.7z",
    "**/*.png",
    "**/*.jpg",
]


def repo_root() -> Path:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if out:
            return Path(out)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass
    return Path(__file__).resolve().parents[2]


def git_diff_names(rev_range: str) -> list[str]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", rev_range],
        text=True,
        cwd=repo_root(),
    )
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, pat) for pat in patterns)


def classify_paths(paths: list[str]) -> dict:
    paths = [p.replace("\\", "/") for p in paths if p.strip()]
    deployable = [p for p in paths if not _matches_any(p, IGNORE_GLOBS)]
    needs_ui_rebuild = any(_matches_any(p, UI_REBUILD_GLOBS) for p in deployable)
    needs_runner_rebuild = any(_matches_any(p, RUNNER_REBUILD_GLOBS) for p in deployable)
    hotpatch_files = [
        p
        for p in deployable
        if _matches_any(p, UI_HOTPATCH_GLOBS) and not _matches_any(p, UI_REBUILD_GLOBS)
    ]
    needs_ui_hotpatch = bool(hotpatch_files) and not needs_ui_rebuild
    return {
        "needs_ui_hotpatch": needs_ui_hotpatch,
        "needs_ui_rebuild": needs_ui_rebuild,
        "needs_runner_rebuild": needs_runner_rebuild,
        "changed_files": paths,
        "deployable_files": deployable,
        "hotpatch_files": hotpatch_files if needs_ui_hotpatch else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "rev_range",
        nargs="?",
        default="HEAD~1..HEAD",
        help="Git revision range (default: HEAD~1..HEAD).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument(
        "--files",
        nargs="*",
        help="Classify explicit paths instead of git diff.",
    )
    args = parser.parse_args()
    if args.files:
        paths = list(args.files)
    else:
        paths = git_diff_names(args.rev_range)
    result = classify_paths(paths)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"rev_range: {args.rev_range}")
        print(f"changed: {len(result['changed_files'])}  deployable: {len(result['deployable_files'])}")
        print(f"needs_ui_hotpatch: {result['needs_ui_hotpatch']}")
        print(f"needs_ui_rebuild: {result['needs_ui_rebuild']}")
        print(f"needs_runner_rebuild: {result['needs_runner_rebuild']}")
        if result["hotpatch_files"]:
            print("hotpatch_files:")
            for f in result["hotpatch_files"]:
                print(f"  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
