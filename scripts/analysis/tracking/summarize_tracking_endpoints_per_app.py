#!/usr/bin/env python3
"""
Summarize tracking endpoints per app from parsed traffic JSON files.

Input traffic files format:
  { "<app>": { "<endpoint>": {...}, ... }, ... }

Categories file format:
  { "<endpoint>": "<category>", ... }

This script aggregates unique tracking endpoints per app across matching traffic files
and writes:
  { "<app>": {"tracking_endpoints": [...], "number": N}, ... }
  
Example:
python summarize_tracking_endpoints_per_app.py \
  --parsed-dir ../parsed_files \
  --categories ../endpoints_categorization/new_endpoints_categories.json \
  --must-contain usa pcapdroid \
  --output tracking_pcapdroid_usa.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple


DEFAULT_TRACKING_LABELS = {"analytics_and_trackers", "tracking", "tracking_and_analytics"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def iter_matching_files(folder: Path, must_contain: List[str]) -> Iterable[Path]:
    for p in sorted(folder.glob("*.json")):
        name = p.name
        if all(token in name for token in must_contain):
            yield p


def is_tracking_endpoint(endpoint: str, categories: Dict[str, str], tracking_labels: Set[str]) -> bool:
    cat = categories.get(endpoint)
    return cat in tracking_labels


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate tracking endpoints per app across parsed traffic files.")
    ap.add_argument(
        "--parsed-dir",
        default="../parsed_files",
        help="Directory containing parsed traffic JSON files (default: ../parsed_files).",
    )
    ap.add_argument(
        "--categories",
        default="../endpoints_categorization/new_endpoints_categories.json",
        help="Endpoint categorization JSON path.",
    )
    ap.add_argument(
        "--must-contain",
        nargs="*",
        default=["usa", "pcapdroid"],
        help="Only process files whose filename contains all these tokens (default: usa pcapdroid).",
    )
    ap.add_argument(
        "--tracking-labels",
        nargs="*",
        default=sorted(DEFAULT_TRACKING_LABELS),
        help="Category labels considered tracking (default: common tracking labels).",
    )
    ap.add_argument(
        "--output",
        default="tracking_endpoints_per_app.json",
        help="Output JSON filename (default: tracking_endpoints_per_app.json).",
    )
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    categories_path = Path(args.categories)
    out_path = Path(args.output)

    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")
    if not categories_path.exists():
        raise SystemExit(f"Categories file not found: {categories_path}")

    categories_raw = load_json(categories_path)
    if not isinstance(categories_raw, dict):
        raise SystemExit("Categories JSON must be a dict: {endpoint: category}")
    categories: Dict[str, str] = {str(k): str(v) for k, v in categories_raw.items()}

    tracking_labels = set(args.tracking_labels)

    # app -> set(endpoints)
    tracking_per_app: Dict[str, Set[str]] = {}

    files = list(iter_matching_files(parsed_dir, args.must_contain))
    if not files:
        raise SystemExit(f"No matching files in {parsed_dir} with tokens {args.must_contain}")

    for fpath in files:
        traffic = load_json(fpath)
        if not isinstance(traffic, dict):
            print(f"Warning: skipping non-dict JSON: {fpath}")
            continue

        for app_name, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue
            app = str(app_name)
            tracking_per_app.setdefault(app, set())

            for endpoint in endpoints.keys():
                ep = str(endpoint)
                if is_tracking_endpoint(ep, categories, tracking_labels):
                    tracking_per_app[app].add(ep)

    # Build output format
    output: Dict[str, Dict[str, Any]] = {}
    counts: List[int] = []

    for app, epset in tracking_per_app.items():
        eps = sorted(epset)
        n = len(eps)
        output[app] = {"tracking_endpoints": eps, "number": n}
        if n > 0:
            counts.append(n)

    save_json(out_path, output)

    apps_total = len(output)
    apps_with_tracking = sum(1 for v in output.values() if v["number"] > 0)

    print(f"Wrote: {out_path}")
    print(f"Apps total: {apps_total}")
    print(f"Apps with >=1 tracking endpoint: {apps_with_tracking} ({(apps_with_tracking/apps_total*100):.2f}%)")

    if counts:
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) >= 2 else 0.0
        print(f"Avg tracking endpoints per tracking app: {mean:.2f}")
        print(f"Std dev: {stdev:.2f}")
        print(f"Max: {max(counts)}")
    else:
        print("No tracking endpoints found under the selected filters/labels.")


if __name__ == "__main__":
    main()
