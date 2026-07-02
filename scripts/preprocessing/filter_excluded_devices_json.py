#!/usr/bin/env python3
"""
Filter a JSON mapping by removing excluded device keys.

Input JSON is expected to be a dict like:
{
  "device_a": {...},
  "device_b": {...}
}

By default, writes a new file (recommended). Use --in-place to overwrite.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_EXCLUDED_DEVICES: List[str] = [
    "ring_doorbell",
    "coffee_maker_lavazza",
    "cosori_air_fryer",
    "nanoleaf_triangles",
    "cosori_airfrier",
    "weekett_kettle",
]


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected top-level JSON object (dict), got: {type(data).__name__}")
    return data


def save_json(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Remove excluded device keys from a JSON file.")
    parser.add_argument("input", help="Path to input JSON file")
    parser.add_argument(
        "-o",
        "--output",
        help="Path to output JSON file (default: <input>.filtered.json)",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite the input file (ignores --output).",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=DEFAULT_EXCLUDED_DEVICES,
        help="Device keys to exclude (default: built-in list).",
    )
    parser.add_argument(
        "--print-removed",
        action="store_true",
        help="Print removed device keys.",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path}")

    data = load_json(in_path)

    excluded = set(args.exclude)
    removed = [k for k in data.keys() if k in excluded]
    kept = {k: v for k, v in data.items() if k not in excluded}

    if args.print_removed:
        for k in removed:
            print(f"REMOVED {k}")

    if args.in_place:
        out_path = in_path
    else:
        out_path = Path(args.output) if args.output else in_path.with_suffix(in_path.suffix + ".filtered.json")

    save_json(out_path, kept)
    print(f"Wrote {out_path} (kept {len(kept)} / removed {len(removed)})")


if __name__ == "__main__":
    main()
