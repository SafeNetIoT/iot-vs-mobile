#!/usr/bin/env python3
"""
fill_unsolved_ips_from_dns_maps.py

Fill missing (null) entries in an unsolved-IP mapping by searching historic DNS maps.

Inputs:
  --unsolved: JSON dict { "<ip>": "<hostname>" or null, ... }
  --dns-dir: folder containing DNS maps (each JSON: { "<ip>": "<hostname>", ... })

Output:
  Updated unsolved JSON written to --out.

Example:
  python fill_unsolved_ips_from_dns_maps.py \
    --unsolved unsolved_ips_same_india_us.json \
    --dns-dir ./dns_map_tmp \
    --out unsolved_ips_same_india_us.json
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
    ap = argparse.ArgumentParser(description="Fill unsolved IPs using historic DNS map JSON files.")
    ap.add_argument("--unsolved", required=True, help="Path to unsolved IP JSON.")
    ap.add_argument("--dns-dir", required=True, help="Folder containing DNS map JSON files.")
    ap.add_argument("--out", required=True, help="Output JSON path.")
    args = ap.parse_args()

    unsolved: Dict[str, Any] = load_json(Path(args.unsolved))
    dns_dir = Path(args.dns_dir)

    dns_files = sorted(dns_dir.glob("*.json"))
    matches = 0

    for ip, val in list(unsolved.items()):
        if val is not None:
            continue

        for dns_file in dns_files:
            dns_map = load_json(dns_file)
            if not isinstance(dns_map, dict):
                continue
            if ip in dns_map:
                unsolved[ip] = dns_map[ip]
                matches += 1
                break

    save_json(Path(args.out), unsolved)
    print(f"Filled {matches} IP(s). Wrote: {args.out}")


if __name__ == "__main__":
    main()
