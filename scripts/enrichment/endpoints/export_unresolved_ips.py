#!/usr/bin/env python3
"""
export_unresolved_ips.py

Export unresolved IPs from a JSON mapping to a newline-separated text file.

Input JSON format:
  { "<ip>": "<hostname>" | null | <non-string>, ... }

An IP is considered "unresolved" if its value is missing, null, or not a string.

Example:
  python export_unresolved_ips.py \
    --input unsolved_ips_pcapdroid_updated.json \
    --output unsolved_ips_pcapdroid_updated.txt
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description="Export unresolved IP keys from a JSON mapping.")
    ap.add_argument("--input", required=True, help="Input JSON file: {ip: hostname|null|...}")
    ap.add_argument("--output", required=True, help="Output text file (one IP per line).")
    args = ap.parse_args()

    mapping = load_json(Path(args.input))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    unresolved = 0
    with out_path.open("w", encoding="utf-8") as out:
        for ip, val in mapping.items():
            if not isinstance(val, str) or val is None:
                out.write(f"{ip}\n")
                unresolved += 1

    print(f"Wrote {unresolved} unresolved IP(s) to {out_path}")


if __name__ == "__main__":
    main()
