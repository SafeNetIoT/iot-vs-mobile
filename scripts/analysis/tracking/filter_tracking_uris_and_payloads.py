#!/usr/bin/env python3
"""
filter_tracking_uris_and_payloads.py

Filter URI+payload logs and keep only entries whose destination domain is
categorized as Tracking & Analytics.

Input:
  - Folder of JSON files (default: ./uris_and_payloads/)
    Each file is expected to contain a list of dicts like:
      [{"uri": "...", "payload": ...}, ...]

  - Categorization file mapping domain -> category
    (default: ../endpoints_categorization/new_endpoints_categories.json)

Output:
  - Writes filtered files into ./tracking_uris_and_payloads/
    using the same filename as the input (only if at least one match exists).

Example:
  python filter_tracking_uris_and_payloads.py \
    --input-dir ./uris_and_payloads \
    --categories ../endpoints_categorization/new_endpoints_categories.json \
    --output-dir ./tracking_uris_and_payloads
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse


TRACKING_LABEL = "analytics_and_trackers"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def extract_host(uri: str) -> str:
    """
    Robustly extract the host from a URI.
    Falls back to your previous trimming behavior if parsing fails.
    """
    try:
        parsed = urlparse(uri)
        if parsed.netloc:
            return parsed.netloc
        # handle URIs without scheme
        parsed2 = urlparse("https://" + uri)
        return parsed2.netloc or uri.split("/")[0]
    except Exception:
        return uri.replace("https://", "").replace("http://", "").split("/")[0]


def main() -> None:
    ap = argparse.ArgumentParser(description="Filter URI+payload entries to Tracking & Analytics destinations.")
    ap.add_argument("--input-dir", default="./uris_and_payloads", help="Folder with URI/payload JSON files.")
    ap.add_argument(
        "--categories",
        default="../endpoints_categorization/new_endpoints_categories.json",
        help="Endpoint categorization JSON (domain -> category).",
    )
    ap.add_argument("--output-dir", default="./tracking_uris_and_payloads", help="Output folder.")
    ap.add_argument("--tracking-label", default=TRACKING_LABEL, help="Category label treated as tracking.")
    args = ap.parse_args()

    input_dir = Path(args.input_dir)
    categories_path = Path(args.categories)
    output_dir = Path(args.output_dir)

    if not input_dir.is_dir():
        raise SystemExit(f"Input folder not found: {input_dir}")
    if not categories_path.exists():
        raise SystemExit(f"Categories file not found: {categories_path}")

    categories_raw = load_json(categories_path)
    if not isinstance(categories_raw, dict):
        raise SystemExit("Categories JSON must be a dict: {domain: category}")
    categories: Dict[str, str] = {str(k): str(v) for k, v in categories_raw.items()}

    written = 0
    for path in sorted(input_dir.glob("*.json")):
        data = load_json(path)
        if not isinstance(data, list):
            continue

        filtered: List[Dict[str, Any]] = []
        seen = set()

        for entry in data:
            if not isinstance(entry, dict) or "uri" not in entry:
                continue

            host = extract_host(str(entry["uri"]))
            if categories.get(host) != args.tracking_label:
                continue

            # de-dup exact entries
            key = json.dumps(entry, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            filtered.append(entry)

        if filtered:
            out_path = output_dir / path.name
            save_json(out_path, filtered)
            written += 1
            print(f"Wrote {out_path} ({len(filtered)} entries)")

    print(f"Done. Wrote {written} file(s).")


if __name__ == "__main__":
    main()
