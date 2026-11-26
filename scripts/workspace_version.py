#!/usr/bin/env python3
"""Print the workspace package version from the repo root Cargo.toml."""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

root = Path(__file__).resolve().parents[1]
data = tomllib.loads(root.joinpath("Cargo.toml").read_text(encoding="utf-8"))
version = data["workspace"]["package"]["version"]
sys.stdout.write(f"{version}\n")