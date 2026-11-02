#!/usr/bin/env python3
"""Compare failed CKV ids between rustmaninoff and Checkov on a shared fixture pack."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "testdata" / "checkov-compare"
EXPECTED = FIXTURES / "expected.json"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def rustmaninoff_failed(bin_path: str) -> set[str]:
    proc = run(
        [
            bin_path,
            "scan",
            str(FIXTURES),
            "--output",
            "json",
            "--soft-fail",
            "--compact",
        ]
    )
    if proc.returncode not in (0, 1):
        print(proc.stderr or proc.stdout, file=sys.stderr)
        raise SystemExit(f"rustmaninoff failed with {proc.returncode}")
    data = json.loads(proc.stdout)
    failed = data.get("results", {}).get("failed_checks", [])
    return {item["check_id"] for item in failed if item.get("check_result") == "FAILED"}


def checkov_failed() -> set[str]:
    checkov = shutil.which("checkov")
    if not checkov:
        raise SystemExit("checkov not on PATH")
    proc = run(
        [
            checkov,
            "-d",
            str(FIXTURES),
            "--framework",
            "terraform",
            "kubernetes",
            "dockerfile",
            "-o",
            "json",
            "--quiet",
            "--compact",
            "--soft-fail",
        ]
    )
    # checkov may return non-zero when findings exist
    raw = proc.stdout.strip() or "[]"
    data = json.loads(raw)
    ids: set[str] = set()
    items = data if isinstance(data, list) else [data]
    for block in items:
        if not isinstance(block, dict):
            continue
        results = block.get("results") or {}
        for finding in results.get("failed_checks") or []:
            cid = finding.get("check_id")
            if cid:
                ids.add(cid)
    return ids


def main() -> int:
    expected = json.loads(EXPECTED.read_text())
    must = set(expected["must_fail_both"])
    bin_path = os.environ.get("RUSTMANINOFF_BIN")
    if not bin_path:
        cand = ROOT / "target" / "release" / "rustmaninoff"
        if not cand.is_file():
            subprocess.check_call(
                ["cargo", "build", "--release", "-p", "rustmaninoff"], cwd=ROOT
            )
        bin_path = str(cand)

    ours = rustmaninoff_failed(bin_path)
    theirs = checkov_failed()

    missing_ours = sorted(must - ours)
    missing_theirs = sorted(must - theirs)
    print(f"rustmaninoff failed ids: {len(ours)}")
    print(f"checkov failed ids: {len(theirs)}")
    print(f"must_fail_both: {sorted(must)}")
    if missing_ours or missing_theirs:
        print("MISSING in rustmaninoff:", missing_ours)
        print("MISSING in checkov:", missing_theirs)
        return 1
    print("OK: all must_fail_both ids failed in both tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
