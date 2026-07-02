#!/usr/bin/env python3
"""
Find apps/endpoints that use the service label '9100:pdl-datastream' in parsed traffic JSON files.

Expected input format:
  { "<app>": { "<endpoint>": {"ports": [...], ...}, ... }, ... }

Default inputs match your existing naming convention:
  parsed_files/<scenario>_<layout>_no_frida_jan2024.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict at top-level in {path}, got {type(data).__name__}")
    return data


def iter_hits(data: Dict[str, Any], needle: str) -> Iterable[Tuple[str, str, str]]:
    """
    Yield (app, endpoint, port_entry) where needle appears in any 'ports' entry.
    """
    for app, endpoints in data.items():
        if not isinstance(endpoints, dict):
            continue
        for endpoint, values in endpoints.items():
            ports = (values or {}).get("ports", [])
            for port_entry in ports or []:
                if needle in str(port_entry):
                    yield str(app), str(endpoint), str(port_entry)


def main() -> None:
    p = argparse.ArgumentParser(description="Find parsed-traffic occurrences of '9100:pdl-datastream'.")
    p.add_argument("--parsed-dir", default="parsed_files", help="Directory containing parsed JSON files.")
    p.add_argument("--month-tag", default="jan2024", help="Month tag used in filenames (default: jan2024).")
    p.add_argument(
        "--scenarios",
        nargs="*",
        default=["same", "different"],
        help="Scenario prefixes to scan (default: same different).",
    )
    p.add_argument(
        "--layouts",
        nargs="*",
        default=["moniotr", "pcapdroid"],
        help="Layouts to scan (default: moniotr pcapdroid).",
    )
    p.add_argument("--needle", default="9100:pdl-datastream", help="Port/service label to search for.")
    args = p.parse_args()

    parsed_dir = Path(args.parsed_dir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    total_hits = 0
    for scenario in args.scenarios:
        for layout in args.layouts:
            path = parsed_dir / f"{scenario}_{layout}_no_frida_{args.month_tag}.json"
            if not path.exists():
                print(f"[skip] missing {path}")
                continue

            data = load_json(path)
            hits = list(iter_hits(data, args.needle))
            if not hits:
                continue

            print(f"\n== {scenario} / {layout} ({path.name}) ==")
            for app, endpoint, port_entry in hits:
                print(f"app={app} endpoint={endpoint} port={port_entry}")
                total_hits += 1

    print(f"\nDone. Total hits: {total_hits}")


if __name__ == "__main__":
    main()
