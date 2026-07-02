#!/usr/bin/env python3
"""
Update a mapping of tracking endpoints to their countries from parsed traffic.

Reads:
  - parsed traffic JSON (e.g., parsed_files/same_pcapdroid_frida_jan2024.json)
  - existing mapping JSON (e.g., tracking_endpoints_with_countries.json)

Writes:
  - updated mapping JSON: { app: { endpoint: country, ... }, ... }

Expected parsed traffic format per endpoint:
  values['categorization'] == 'analytics_and_trackers'
  values['country'] exists
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def main() -> None:
    p = argparse.ArgumentParser(description="Update app tracking endpoints with country information.")
    p.add_argument("--traffic", required=True, help="Parsed traffic JSON path.")
    p.add_argument("--mapping", required=True, help="Existing mapping JSON path (will be updated).")
    p.add_argument(
        "--only-country",
        default=None,
        help="If set, only add endpoints whose country matches this value (e.g., China).",
    )
    p.add_argument(
        "--category",
        default="analytics_and_trackers",
        help="Categorization label to match (default: analytics_and_trackers).",
    )
    args = p.parse_args()

    traffic_path = Path(args.traffic)
    mapping_path = Path(args.mapping)

    traffic: Dict[str, Any] = load_json(traffic_path)
    mapping: Dict[str, Dict[str, str]] = load_json(mapping_path)

    if not isinstance(mapping, dict):
        raise SystemExit("Mapping JSON must be a dict: {app: {endpoint: country}}")

    added = 0
    for app, endpoints in (traffic or {}).items():
        if not isinstance(endpoints, dict):
            continue
        mapping.setdefault(app, {})
        for endpoint, values in endpoints.items():
            if not isinstance(values, dict):
                continue
            if values.get("categorization") != args.category:
                continue
            if endpoint in mapping[app]:
                continue

            country = values.get("country")
            if not country:
                continue
            if args.only_country and country != args.only_country:
                continue

            print(f"Add: app={app} endpoint={endpoint} country={country}")
            mapping[app][endpoint] = country
            added += 1

    save_json(mapping_path, mapping)
    print(f"Wrote {mapping_path} (added {added} new endpoints)")


if __name__ == "__main__":
    main()
