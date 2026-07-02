#!/usr/bin/env python3
"""
merge_resolved_hosts_into_categories.py

Add resolved hostnames from one or more "unsolved IP" maps into an endpoint categories dict.

Logic matches old script:
  - For each ip->hostname where hostname is a string and not already present:
      categories[hostname] = None   (default-category)

Example (old behavior equivalent):
  python merge_resolved_hosts_into_categories.py \
    --categories endpoint_categories_updated.json \
    --unsolved unsolved_ips_moniotr_updated.json unsolved_ips_pcapdroid_updated.json unsolved_ips_same_india_us.json \
    --out endpoint_categories.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge resolved hostnames into endpoint category dictionary.")
    ap.add_argument("--categories", default="endpoint_categories_updated.json", help="Input category JSON.")
    ap.add_argument("--unsolved", nargs="+", required=True, help="One or more unsolved-ip JSON maps.")
    ap.add_argument("--default-category", default=None, help="Category value to assign to newly added hostnames.")
    ap.add_argument("--out", default="endpoint_categories.json", help="Output category JSON.")
    ap.add_argument("--in-place", action="store_true", help="Overwrite the input categories file.")
    args = ap.parse_args()

    categories_path = Path(args.categories)
    categories = load_json(categories_path)
    if not isinstance(categories, dict):
        raise SystemExit("Categories must be a JSON dict: {endpoint: category|null}")

    added = 0
    for upath in args.unsolved:
        mapping = load_json(Path(upath))
        if not isinstance(mapping, dict):
            continue

        for _ip, hostname in mapping.items():
            if isinstance(hostname, str) and hostname:
                if hostname not in categories:
                    print("Added", hostname)
                    categories[hostname] = args.default_category
                    added += 1

    out_path = categories_path if args.in_place else Path(args.out)
    save_json(out_path, categories)
    print(f"Wrote: {out_path} (added {added})")


if __name__ == "__main__":
    main()
