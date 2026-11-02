#!/usr/bin/env python3
"""Inventory rustmaninoff CKV policy IDs for the fidelity table (#42).

Emits Markdown to stdout. Does not fetch Checkov's catalog yet; that lands
when a pinned Checkov inventory is added under tools/checkov-ids/.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "crates" / "cli" / "policies"


def policy_ids() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted(POLICIES.rglob("*.yaml")):
        framework = path.parent.name
        rows.append((framework, path.stem))
    return rows


def family(check_id: str) -> str:
    if check_id.startswith("CKV2_"):
        return "CKV2"
    for prefix in ("CKV_AWS_", "CKV_AZURE_", "CKV_GCP_", "CKV_K8S_", "CKV_DOCKER_", "CKV_"):
        if check_id.startswith(prefix.rstrip("_") + "_") or check_id.startswith(prefix):
            if prefix == "CKV_":
                return "CKV_other"
            return prefix.rstrip("_")
    return "other"


def render_markdown(rows: list[tuple[str, str]]) -> str:
    by_fw: dict[str, list[str]] = defaultdict(list)
    by_fam: dict[str, int] = defaultdict(int)
    for fw, cid in rows:
        by_fw[fw].append(cid)
        by_fam[family(cid)] += 1

    lines = [
        "# Checkov coverage inventory (rustmaninoff)",
        "",
        f"Generated from `{POLICIES.relative_to(ROOT)}`.",
        f"**Built-in checks:** {len(rows)}",
        "",
        "## By framework directory",
        "",
        "| Framework | Count |",
        "| --- | ---: |",
    ]
    for fw in sorted(by_fw):
        lines.append(f"| {fw} | {len(by_fw[fw])} |")

    lines += [
        "",
        "## By CKV family",
        "",
        "| Family | Count |",
        "| --- | ---: |",
    ]
    for fam in sorted(by_fam):
        lines.append(f"| {fam} | {by_fam[fam]} |")

    lines += [
        "",
        "## Notes",
        "",
        "- Checkov denominator and gap columns are filled when `tools/checkov-ids/` is added (#42).",
        "- Graph checks (`CKV2_*`) are a first-wave AWS subset, not full Checkov graph parity.",
        "- Intentional gaps (Helm, plan JSON, secrets, CVE) stay out of this inventory.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write Markdown here (default: stdout)",
    )
    args = parser.parse_args()
    md = render_markdown(policy_ids())
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(md + "\n")
    else:
        print(md)


if __name__ == "__main__":
    main()
