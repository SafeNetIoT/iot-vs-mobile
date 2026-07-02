#!/usr/bin/env python3
"""
sum_bytes_to_tracking_endpoints.py

Compute total bytes sent to Tracking & Analytics endpoints, per endpoint,
from parsed traffic JSON files.

Input:
  - A folder of parsed traffic JSON files (default: ../parsed_files/)
  - A categorization file mapping endpoint -> category
    (default: ../endpoints_categorization/new_endpoints_categories.json)

The script finds endpoints whose category is "analytics_and_trackers" and
sums their packet sizes across all matching traffic files.

Example:
  python sum_bytes_to_tracking_endpoints.py \
    --parsed-dir ../parsed_files \
    --categories ../endpoints_categorization/new_endpoints_categories.json \
    --experiment different \
    --output-dir .

Outputs:
  - bytes_tracking_moniotr_<experiment>.json
  - bytes_tracking_pcapdroid_<experiment>.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


TRACKING_LABEL = "analytics_and_trackers"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def add_packet_sizes(total_bytes: int, packet_sizes: Dict[str, Any]) -> int:
    """
    packet_sizes is expected to be a dict like:
      { "<filename>": [<pkt_len>, <pkt_len>, ...], ... }
    """
    if not isinstance(packet_sizes, dict):
        return total_bytes

    for _, sizes in packet_sizes.items():
        if not isinstance(sizes, list):
            continue
        for s in sizes:
            try:
                total_bytes += int(s)
            except Exception:
                continue
    return total_bytes


def main() -> None:
    ap = argparse.ArgumentParser(description="Sum bytes to tracking endpoints from parsed traffic JSON files.")
    ap.add_argument("--parsed-dir", default="../parsed_files", help="Directory with parsed traffic JSON files.")
    ap.add_argument(
        "--categories",
        default="../endpoints_categorization/new_endpoints_categories.json",
        help="Endpoint categorization JSON (endpoint -> category).",
    )
    ap.add_argument(
        "--experiment",
        default="different",
        help="Substring used to select matching traffic files (e.g., same/different).",
    )
    ap.add_argument("--output-dir", default=".", help="Where to write output JSON files.")
    ap.add_argument("--tracking-label", default=TRACKING_LABEL, help="Category label treated as tracking.")
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    categories_path = Path(args.categories)
    out_dir = Path(args.output_dir)

    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")
    if not categories_path.exists():
        raise SystemExit(f"Categories file not found: {categories_path}")

    categories_raw = load_json(categories_path)
    if not isinstance(categories_raw, dict):
        raise SystemExit("Categories JSON must be a dict: {endpoint: category}")
    categories: Dict[str, str] = {str(k): str(v) for k, v in categories_raw.items()}

    moniotr_bytes: Dict[str, int] = {}
    pcapdroid_bytes: Dict[str, int] = {}

    for path in sorted(parsed_dir.glob("*.json")):
        name = path.name
        if args.experiment not in name:
            continue

        traffic = load_json(path)
        if not isinstance(traffic, dict):
            continue

        is_moniotr = "moniotr" in name
        is_pcapdroid = "pcapdroid" in name
        if not (is_moniotr or is_pcapdroid):
            continue

        for _, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue

            for endpoint, values in endpoints.items():
                endpoint = str(endpoint)
                if categories.get(endpoint) != args.tracking_label:
                    continue
                if not isinstance(values, dict):
                    continue

                pkt_sizes = values.get("packet_sizes", {})
                if is_moniotr:
                    moniotr_bytes[endpoint] = add_packet_sizes(moniotr_bytes.get(endpoint, 0), pkt_sizes)
                else:
                    pcapdroid_bytes[endpoint] = add_packet_sizes(pcapdroid_bytes.get(endpoint, 0), pkt_sizes)

    moniotr_sorted = dict(sorted(moniotr_bytes.items(), key=lambda kv: kv[1], reverse=True))
    pcapdroid_sorted = dict(sorted(pcapdroid_bytes.items(), key=lambda kv: kv[1], reverse=True))

    save_json(out_dir / f"bytes_tracking_moniotr_{args.experiment}.json", moniotr_sorted)
    save_json(out_dir / f"bytes_tracking_pcapdroid_{args.experiment}.json", pcapdroid_sorted)

    print(f"Wrote: {out_dir / f'bytes_tracking_moniotr_{args.experiment}.json'}")
    print(f"Wrote: {out_dir / f'bytes_tracking_pcapdroid_{args.experiment}.json'}")


if __name__ == "__main__":
    main()
