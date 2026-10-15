#!/usr/bin/env python3
"""Render img/linkedin-release-banner.jpg (1200x627 LinkedIn share image).

Usage:
  python3 scripts/render-linkedin-banner.py
  python3 scripts/render-linkedin-banner.py --version 0.2.0 --subtitle "Data sources and Dockerfiles"
  python3 scripts/render-linkedin-banner.py --version 0.2.0 --out /tmp/rustmaninoff-0.2.0.jpg
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "img" / "logo.jpg"
OUT_DEFAULT = ROOT / "img" / "linkedin-release-banner.jpg"

W, H = 1200, 627
BG = "#161616"
INK = "#EDE8E0"
MUTED = "#C9B8A8"
FOOT = "#8A8178"
ACCENT = "#C47A4A"
NAME = "Rustmaninoff"
SUBTITLE_DEFAULT = "IaC security scanner"
URL_DEFAULT = "github.com/jose-compu/rustmaninoff"

DIDOT = "/System/Library/Fonts/Supplemental/Didot.ttc"
TIMES = "/System/Library/Fonts/Supplemental/Times New Roman.ttf"


def magick(*args: str) -> None:
    subprocess.run(["magick", *args], check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="vX.Y.Z")
    parser.add_argument("--subtitle", default=SUBTITLE_DEFAULT)
    parser.add_argument("--url", default=URL_DEFAULT)
    parser.add_argument("--out", default=str(OUT_DEFAULT))
    args = parser.parse_args()
    version = args.version if str(args.version).startswith("v") else f"v{args.version}"
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    magick(
        "-size",
        f"{W}x{H}",
        f"xc:{BG}",
        "(",
        str(LOGO),
        "-resize",
        "x480",
        ")",
        "-gravity",
        "west",
        "-geometry",
        "+36+0",
        "-composite",
        "-fill",
        INK,
        "-font",
        DIDOT,
        "-pointsize",
        "28",
        "-gravity",
        "northwest",
        "-annotate",
        "+620+150",
        NAME,
        "-fill",
        INK,
        "-font",
        DIDOT,
        "-pointsize",
        "52",
        "-annotate",
        "+620+200",
        "NEW RELEASE",
        "-stroke",
        ACCENT,
        "-strokewidth",
        "2",
        "-fill",
        "none",
        "-draw",
        "line 620,268 1080,268",
        "-stroke",
        "none",
        "-fill",
        INK,
        "-font",
        DIDOT,
        "-pointsize",
        "36",
        "-annotate",
        "+620+290",
        version,
        "-fill",
        MUTED,
        "-font",
        TIMES,
        "-pointsize",
        "24",
        "-annotate",
        "+620+350",
        args.subtitle,
        "-fill",
        FOOT,
        "-font",
        TIMES,
        "-pointsize",
        "18",
        "-annotate",
        "+620+560",
        args.url,
        str(out),
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
