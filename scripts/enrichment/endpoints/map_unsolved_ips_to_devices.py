#!/usr/bin/env python3
"""
map_unsolved_ips_to_devices.py

Map unsolved IP endpoints to the devices/apps that contacted them by scanning parsed traffic files.

Input:
  --unsolved: JSON dict { "<ip>": <value or null>, ... }
  --parsed-dir: folder containing parsed traffic JSON files

Output:
  JSON dict:
    { "<ip>": {"devices":[...]} , ... } (only for entries whose original value is not a string)

Example:
  python map_unsolved_ips_to_devices.py \
    --unsolved unsolved_ips_same_india_us.json \
    --parsed-dir ./parsed_files \
    --include same usa india \
    --out same_us_india_with_extra_data.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Map unsolved IP endpoints to devices/apps that contacted them.")
    ap.add_argument("--unsolved", required=True, help="Unsolved IP JSON file.")
    ap.add_argument("--parsed-dir", required=True, help="Directory containing parsed traffic JSON files.")
    ap.add_argument("--include", nargs="*", default=[], help="Only scan parsed files containing these tokens.")
    ap.add_argument("--out", required=True, help="Output JSON path.")
    args = ap.parse_args()

    missing: Dict[str, Any] = load_json(Path(args.unsolved))
    parsed_dir = Path(args.parsed_dir)

    parsed_files = sorted(parsed_dir.glob("*.json"))
    if args.include:
        parsed_files = [p for p in parsed_files if all(tok in p.name for tok in args.include)]

    result: Dict[str, Dict[str, List[str]]] = {}

    for ip, v in missing.items():
        # keep your original logic: skip if value is already a resolved string
        if isinstance(v, str):
            continue
        result[ip] = {}

        for pf in parsed_files:
            traffic = load_json(pf)
            if not isinstance(traffic, dict):
                continue
            for device, endpoints in traffic.items():
                if not isinstance(endpoints, dict):
                    continue
                if ip in endpoints:
                    result[ip].setdefault("devices", [])
                    if device not in result[ip]["devices"]:
                        result[ip]["devices"].append(device)

    save_json(Path(args.out), result)
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
