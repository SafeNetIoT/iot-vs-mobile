#!/usr/bin/env python3
"""
count_protocols_or_ports_in_parsed_traffic.py

Count protocol or port occurrences in parsed traffic JSON files.

Expected input file format:
  {
    "<app>": {
      "<endpoint>": {
        "protocols": ["HTTPS", "HTTP", ...],
        "ports": ["443:https", "80:http", 1883, ...],
        ...
      },
      ...
    },
    ...
  }

By default, counts protocols. Use --mode ports to count ports instead.

Examples:
  # Count protocols
  python count_protocols_or_ports_in_parsed_traffic.py \
    --parsed-dir ../endpoint_analysis/parsed_files \
    --include same different \
    --mode protocols \
    --output protocols_distribution.json

  # Count ports
  python count_protocols_or_ports_in_parsed_traffic.py \
    --parsed-dir ../endpoint_analysis/parsed_files \
    --include same different \
    --mode ports \
    --output ports_distribution.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict at top-level in {path}, got {type(data).__name__}")
    return data


def normalize_port_entry(p: Any) -> str:
    """
    Normalize a port entry to a compact string key.

    Handles:
      - integers (443)
      - strings ("443:https", "8883", "9100:pdl-datastream")
      - other types (fallback to str)
    """
    s = str(p).strip()
    # Often the script stored "443:https"; keep as-is to preserve service label.
    # If you want raw port only, split on ":" here.
    return s


def iter_values(values: Dict[str, Any], mode: str) -> Iterable[str]:
    if mode == "protocols":
        for proto in values.get("protocols", []) or []:
            yield str(proto).strip()
    else:  # mode == "ports"
        for port in values.get("ports", []) or []:
            yield normalize_port_entry(port)


def main() -> None:
    ap = argparse.ArgumentParser(description="Count protocol or port occurrences in parsed traffic JSON files.")
    ap.add_argument(
        "--parsed-dir",
        default="../endpoint_analysis/parsed_files",
        help="Directory containing parsed traffic JSON files.",
    )
    ap.add_argument(
        "--include",
        nargs="*",
        default=["same", "different"],
        help="Only process files whose name contains at least one of these tokens (default: same different).",
    )
    ap.add_argument(
        "--mode",
        choices=["protocols", "ports"],
        default="protocols",
        help="Count 'protocols' (default) or 'ports'.",
    )
    ap.add_argument(
        "--output",
        default="distribution.json",
        help="Output JSON file (default: distribution.json).",
    )
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    out: Dict[str, Dict[str, int]] = {}

    for path in sorted(parsed_dir.glob("*.json")):
        if args.include and not any(tok in path.name for tok in args.include):
            continue

        traffic = load_json(path)
        counts: Dict[str, int] = {}

        for _app, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue

            for _endpoint, values in endpoints.items():
                if not isinstance(values, dict):
                    continue

                for key in iter_values(values, args.mode):
                    if not key:
                        continue
                    counts[key] = counts.get(key, 0) + 1

        out[path.name] = dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
