#!/usr/bin/env python3
"""Detect UTF-16 BOM and null bytes in source files (deploy pre-flight, local manual)."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

RULE_DOC = ".cursor/rules/file-encoding.mdc"
SCAN_SUFFIXES = {
    ".py", ".tf", ".yml", ".yaml", ".json", ".sh", ".ps1", ".toml", ".cfg", ".ini",
    ".html", ".css", ".js", ".ts", ".md",
}
SKIP_DIR_NAMES = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
    ".mypy_cache", ".tmp-tests", "dast-data", "results", "imports",
}
UTF16_LE_BOM = b"\xff\xfe"
UTF16_BE_BOM = b"\xfe\xff"


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


def should_scan(path: Path, *, explicit: bool = False) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() not in SCAN_SUFFIXES:
        return False
    if not explicit:
        for part in path.parts:
            if part in SKIP_DIR_NAMES:
                return False
    return True


def inspect_bytes(data: bytes) -> str | None:
    if len(data) >= 2:
        if data[:2] == UTF16_LE_BOM:
            return "UTF-16 LE BOM (FF FE)"
        if data[:2] == UTF16_BE_BOM:
            return "UTF-16 BE BOM (FE FF)"
    if b"\x00" in data:
        return "contains null byte (likely UTF-16 corruption)"
    return None


def inspect_file(path: Path) -> str | None:
    try:
        return inspect_bytes(path.read_bytes())
    except OSError as exc:
        return f"unreadable: {exc}"


def iter_all_files(root: Path):
    for path in root.rglob("*"):
        if should_scan(path):
            yield path


def resolve_inputs(root: Path, paths: list[str], scan_all: bool) -> list[Path]:
    if scan_all:
        return sorted(iter_all_files(root))
    resolved: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = root / p
        if p.is_dir():
            resolved.extend(sorted(iter_all_files(p)))
        elif should_scan(p, explicit=True):
            resolved.append(p)
    return resolved


def format_failure(path: Path, reason: str, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return f"  {rel}: {reason}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan entire repository tree (CI mode).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan (default: none unless --all).",
    )
    args = parser.parse_args()
    root = repo_root()

    if not args.all and not args.paths:
        print(
            "check_no_null_bytes: pass --all or one or more file paths.",
            file=sys.stderr,
        )
        return 2

    targets = resolve_inputs(root, args.paths, args.all)
    failures: list[str] = []
    for path in targets:
        reason = inspect_file(path)
        if reason:
            failures.append(format_failure(path, reason, root))

    if failures:
        print("ERROR: UTF-16 / null-byte encoding check failed.\n", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        print(
            f"\nSee {RULE_DOC} - restore UTF-8 no-BOM, e.g.:\n"
            "  git checkout HEAD -- <file>\n"
            "  python scripts/checks/check_no_null_bytes.py --all",
            file=sys.stderr,
        )
        return 1

    label = "repository" if args.all else f"{len(targets)} file(s)"
    print(f"encoding OK ({label})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
