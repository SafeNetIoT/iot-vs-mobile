#!/usr/bin/env python3
"""
rename_devices_in_parsed_json.py

Rename top-level keys in a parsed JSON file using a mapping.

Inputs:
  --input: JSON dict { "<old_name>": <value>, ... }
  --mapping: JSON dict { "<old_name>": "<new_name>", ... }

Example:
  python rename_devices_in_parsed_json.py \
    --input parsed-files/different_pcapdroid_no_frida_jan2024.json \
    --mapping device_name_mapping.json \
    --out parsed-files/different_pcapdroid_no_frida_jan2024.renamed.json \
    --keep-unmapped
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Rename top-level keys in a parsed JSON file.")
    ap.add_argument("--input", required=True, help="Input JSON file.")
    ap.add_argument("--mapping", required=True, help="Mapping JSON file (old -> new).")
    ap.add_argument("--out", default=None, help="Output JSON file. If omitted, use --in-place.")
    ap.add_argument("--in-place", action="store_true", help="Overwrite the input file.")
    ap.add_argument("--keep-unmapped", action="store_true", help="Keep keys not present in mapping.")
    args = ap.parse_args()

    in_path = Path(args.input)
    mapping_path = Path(args.mapping)

    data: Dict[str, Any] = load_json(in_path)
    mapping: Dict[str, str] = load_json(mapping_path)

    if not isinstance(data, dict) or not isinstance(mapping, dict):
        raise SystemExit("Both input and mapping must be JSON objects (dicts).")

    out: Dict[str, Any] = {}
    collisions = 0

    for old_key, value in data.items():
        if old_key in mapping:
            new_key = mapping[old_key]
        else:
            if not args.keep_unmapped:
                continue
            new_key = old_key

        if new_key in out:
            collisions += 1
            # merge strategy: keep existing; you can change this to merge dicts if needed
            continue
        out[new_key] = value

    out_path = in_path if args.in_place else (Path(args.out) if args.out else None)
    if out_path is None:
        raise SystemExit("Provide --out or use --in-place.")

    save_json(out_path, out)
    print(f"Wrote: {out_path} (keys: {len(out)}; collisions skipped: {collisions})")


if __name__ == "__main__":
    main()
