#!/usr/bin/env python3
"""
summarize_endpoint_categories.py

Summarize unique endpoints by category across selected parsed files.

Default matches old behavior:
  - scans ../parsed_files/
  - only files with both "pcapdroid" and "india" in filename
  - prints: total unique endpoints, non-local IPs, local IPs

Example (old behavior):
  python summarize_endpoint_categories.py

Example (WAN moniotr, write JSON):
  python summarize_endpoint_categories.py \
    --must-contain different moniotr \
    --out categories_summary.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Set

from netaddr import IPAddress


LOCAL_PREFIXES = (
    "192.168", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_local_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in LOCAL_PREFIXES)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize endpoint categories across selected parsed files.")
    ap.add_argument("--parsed-dir", default="../parsed_files", help="Folder with parsed JSON files.")
    ap.add_argument("--glob", default="*.json", help="Glob pattern (default: *.json).")
    ap.add_argument("--categories", default="new_endpoints_categories.json", help="Endpoint->category JSON.")
    ap.add_argument("--must-contain", nargs="*", default=["pcapdroid", "india"], help="Filename tokens filter.")
    ap.add_argument("--must-not-contain", nargs="*", default=[], help="Skip filenames containing any token.")
    ap.add_argument("--out", default=None, help="Optional JSON output path for the summary.")
    args = ap.parse_args()

    categories_map = load_json(Path(args.categories))
    if not isinstance(categories_map, dict):
        raise SystemExit("Categories JSON must be a dict: {endpoint: category}")

    parsed_dir = Path(args.parsed_dir)

    analyzed_endpoints: Set[str] = set()
    category_counts: Dict[str, int] = {}
    apps_per_category: Dict[str, Set[str]] = {}
    count_ips = 0
    count_ips_local = 0

    for file in sorted(parsed_dir.glob(args.glob)):
        if args.must_contain and not all(tok in file.name for tok in args.must_contain):
            continue
        if args.must_not_contain and any(tok in file.name for tok in args.must_not_contain):
            continue

        traffic = load_json(file)
        if not isinstance(traffic, dict):
            continue

        for app_name, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue

            for endpoint in endpoints.keys():
                endpoint = str(endpoint)
                if endpoint in analyzed_endpoints:
                    continue
                analyzed_endpoints.add(endpoint)

                # classify IPs separately (same logic)
                try:
                    IPAddress(endpoint)
                    if is_local_ip(endpoint):
                        count_ips_local += 1
                        apps_per_category.setdefault("local IPs", set()).add(app_name)
                    else:
                        count_ips += 1
                        apps_per_category.setdefault("IPs", set()).add(app_name)
                    continue
                except Exception:
                    pass

                # domain endpoint -> category
                cat = categories_map.get(endpoint)
                if cat is None:
                    # keep same behavior: print unknown endpoints
                    print(endpoint)
                    continue

                category_counts[cat] = category_counts.get(cat, 0) + 1
                apps_per_category.setdefault(cat, set()).add(app_name)

    print(len(analyzed_endpoints))
    print("IPs", count_ips)
    print("Local IPs", count_ips_local)

    if args.out:
        out_obj = {
            "unique_endpoints": len(analyzed_endpoints),
            "ips_non_local": count_ips,
            "ips_local": count_ips_local,
            "category_counts": dict(sorted(category_counts.items(), key=lambda kv: kv[1], reverse=True)),
            "apps_per_category": {k: sorted(list(v)) for k, v in apps_per_category.items()},
        }
        Path(args.out).write_text(json.dumps(out_obj, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
