#!/usr/bin/env python3
"""Conservative repository pre-publish check.

This does not replace a dedicated secret scanner. It catches common accidental
runtime files, private keys, and several high-confidence token formats.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES = {".env", "agent.json", "agent-release.json", "agent-release.sig"}
FORBIDDEN_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".der",
    ".db", ".sqlite", ".sqlite3", ".zip",
}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
}


def files_to_check() -> list[Path]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files"], text=True, stderr=subprocess.DEVNULL
        )
        files = [ROOT / line for line in out.splitlines() if line.strip()]
        if files:
            return files
    except Exception:
        pass
    return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


def main() -> int:
    failures: list[str] = []
    for path in files_to_check():
        rel = path.relative_to(ROOT)
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden runtime/secret file: {rel}")
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                failures.append(f"possible {label}: {rel}")

    if failures:
        print("Pre-publish check FAILED:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Pre-publish check OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
