#!/usr/bin/env python3
"""
apply_endpoint_categories.py

Apply endpoint categories (endpoint -> category) to parsed traffic JSON files.

Default behavior matches your old script:
  - reads categories JSON
  - scans ../parsed_files/*.json
  - overwrites each file in place

Example (old behavior):
  python apply_endpoint_categories.py

Example (write to new directory, only update missing categorization):
  python apply_endpoint_categories.py \
    --parsed-dir ../parsed_files \
    --outdir ../parsed_files_categorized \
    --only-missing
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def iter_files(folder: Path, pattern: str, must_contain: list[str], must_not_contain: list[str]) -> Iterable[Path]:
    for p in sorted(folder.glob(pattern)):
        name = p.name
        if must_contain and not all(tok in name for tok in must_contain):
            continue
        if must_not_contain and any(tok in name for tok in must_not_contain):
            continue
        yield p


def apply_categories(traffic: Dict[str, Any], categories: Dict[str, Any], only_missing: bool) -> Dict[str, Any]:
    for _app, endpoints in traffic.items():
        if not isinstance(endpoints, dict):
            continue
        for endpoint, values in endpoints.items():
            if not isinstance(values, dict):
                continue
            if endpoint not in categories:
                continue
            if only_missing and values.get("categorization") is not None:
                continue
            values["categorization"] = categories[endpoint]
    return traffic


def main() -> None:
    ap = argparse.ArgumentParser(description="Apply endpoint categories to parsed traffic JSON files.")
    ap.add_argument("--categories", default="new_endpoints_categories.json", help="Endpoint->category JSON.")
    ap.add_argument("--parsed-dir", default="../parsed_files", help="Folder with parsed JSON files.")
    ap.add_argument("--glob", default="*.json", help="Glob pattern for parsed files (default: *.json).")
    ap.add_argument("--must-contain", nargs="*", default=[], help="Only process files whose names contain all tokens.")
    ap.add_argument("--must-not-contain", nargs="*", default=[], help="Skip files whose names contain any token.")
    ap.add_argument("--only-missing", action="store_true", help="Only fill categorization if missing.")
    ap.add_argument("--in-place", action="store_true", help="Overwrite input files (default if --outdir not set).")
    ap.add_argument("--outdir", default=None, help="Write updated JSONs to this folder instead of overwriting.")
    args = ap.parse_args()

    categories = load_json(Path(args.categories))
    if not isinstance(categories, dict):
        raise SystemExit("Categories JSON must be a dict: {endpoint: category}")

    parsed_dir = Path(args.parsed_dir)
    outdir = Path(args.outdir) if args.outdir else None
    in_place = args.in_place or (outdir is None)  # keep old default

    for path in iter_files(parsed_dir, args.glob, args.must_contain, args.must_not_contain):
        traffic = load_json(path)
        if not isinstance(traffic, dict):
            continue
        updated = apply_categories(traffic, categories, args.only_missing)

        out_path = path if in_place else (outdir / path.name)  # type: ignore[arg-type]
        save_json(out_path, updated)
        print(f"Updated: {out_path}")


if __name__ == "__main__":
    main()
