#!/usr/bin/env python3
"""Refresh tools/checkov-ids/snapshot.json from bridgecrewio/checkov@main."""

from __future__ import annotations

import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "tools" / "checkov-ids"
TREE_URL = "https://api.github.com/repos/bridgecrewio/checkov/git/trees/main?recursive=1"
RAW = "https://raw.githubusercontent.com/bridgecrewio/checkov/main/"
ID_RE = re.compile(r'id\s*=\s*"(CKV[_2][^"]+)"')
UA = {"User-Agent": "rustmaninoff-fetch-checkov-ids", "Accept": "application/vnd.github+json"}


def get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]})
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode()


def main() -> None:
    tree = get_json(TREE_URL)["tree"]
    paths = [t["path"] for t in tree if t["type"] == "blob" and t["path"].endswith(".py")]
    groups = {
        "docker": [
            p
            for p in paths
            if p.startswith("checkov/dockerfile/checks/")
            and not p.endswith("__init__.py")
            and "/graph_checks/" not in p
        ],
        "kubernetes": [
            p
            for p in paths
            if p.startswith("checkov/kubernetes/checks/")
            and not p.endswith("__init__.py")
            and "/graph_checks/" not in p
        ],
        "terraform_aws": [
            p
            for p in paths
            if p.startswith("checkov/terraform/checks/resource/")
            and not p.endswith("__init__.py")
        ],
    }

    def ids_for(path: str) -> list[str]:
        return ID_RE.findall(get_text(RAW + path))

    out: dict[str, list[str]] = {}
    for name, plist in groups.items():
        found: list[str] = []
        with ThreadPoolExecutor(24) as pool:
            futs = [pool.submit(ids_for, p) for p in plist]
            for fut in as_completed(futs):
                found.extend(fut.result())
        out[name] = sorted(set(found))
        print(f"{name}: {len(plist)} files -> {len(out[name])} ids")

    DEST.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": {
            "source": "bridgecrewio/checkov@main",
            "purpose": "Fidelity denominator for docs/fidelity.md (#42)",
        },
        "ids": out,
    }
    (DEST / "snapshot.json").write_text(json.dumps(payload, indent=2) + "\n")
    for key, ids in out.items():
        (DEST / f"{key}.txt").write_text("\n".join(ids) + "\n")
    print(f"wrote {DEST}")


if __name__ == "__main__":
    main()
