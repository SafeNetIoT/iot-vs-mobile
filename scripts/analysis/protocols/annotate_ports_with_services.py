#!/usr/bin/env python3
"""
annotate_ports_with_services.py

Add service names to observed ports in parsed endpoint-analysis JSON files.

What it does:
  - Loads a port->service map (e.g., ports_map.json).
    Keys can be single ports ("443") or ranges ("8000-8100").
  - Scans parsed traffic JSON files in a directory.
  - Rewrites each endpoint's "ports" list, converting items like:
        "443" -> "443:https"
        "9100" -> "9100:pdl-datastream"   (if your map contains it)

Expected parsed JSON format:
  { "<app>": { "<endpoint>": {"ports": [...], ...}, ...}, ... }

Example:
  # In-place update
  python annotate_ports_with_services.py \
    --parsed-dir ./endpoint_analysis/parsed_files \
    --port-map services_and_ports/ports_map.json \
    --in-place

  # Write to a new directory (recommended)
  python annotate_ports_with_services.py \
    --parsed-dir ./endpoint_analysis/parsed_files \
    --port-map services_and_ports/ports_map.json \
    --outdir ./endpoint_analysis/parsed_files_with_services
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class PortRule:
    start: int
    end: int
    service: Optional[str]  # allow None in mapping


def load_port_rules(port_map_path: Path) -> List[PortRule]:
    """
    Load port rules from a JSON mapping like:
      { "443": "https", "8000-8100": "custom-service", ... }
    """
    raw = json.loads(port_map_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Port map must be a JSON object: {port_or_range: service}")

    rules: List[PortRule] = []
    for k, v in raw.items():
        key = str(k).strip()
        service = None if v is None else str(v).strip()

        if "-" in key:
            a, b = key.split("-", 1)
            rules.append(PortRule(int(a), int(b), service))
        else:
            p = int(key)
            rules.append(PortRule(p, p, service))

    # Put exact ports first, then ranges (slightly nicer determinism)
    rules.sort(key=lambda r: (r.start != r.end, r.start, r.end))
    return rules


def parse_port_value(p: Any) -> Optional[int]:
    """
    Accepts port entries like:
      - 443
      - "443"
      - "443:https"
      - "9100:pdl-datastream"
    Returns the numeric port, or None if it cannot be parsed.
    """
    s = str(p).strip()
    if not s:
        return None
    if ":" in s:
        s = s.split(":", 1)[0]
    try:
        return int(s)
    except ValueError:
        return None


def find_service(port: int, rules: List[PortRule]) -> Optional[str]:
    for r in rules:
        if r.start <= port <= r.end:  # inclusive
            return r.service
    return None


def annotate_ports(ports: List[Any], rules: List[PortRule], keep_unknown: bool) -> List[str]:
    out: List[str] = []
    for p in ports:
        port_num = parse_port_value(p)
        if port_num is None:
            # preserve weird entries as-is
            out.append(str(p))
            continue

        service = find_service(port_num, rules)
        if service:
            out.append(f"{port_num}:{service}")
        else:
            if keep_unknown:
                out.append(str(port_num))
            # else: drop unknown ports
    # de-duplicate while preserving order
    seen = set()
    dedup = []
    for x in out:
        if x not in seen:
            seen.add(x)
            dedup.append(x)
    return dedup


def main() -> None:
    ap = argparse.ArgumentParser(description="Annotate parsed traffic ports with service names.")
    ap.add_argument("--parsed-dir", required=True, help="Directory containing parsed *.json files.")
    ap.add_argument("--port-map", required=True, help="JSON mapping of ports/ranges to service names.")
    ap.add_argument("--in-place", action="store_true", help="Overwrite files in --parsed-dir.")
    ap.add_argument("--outdir", default=None, help="Output directory (recommended if not using --in-place).")
    ap.add_argument("--keep-unknown", action="store_true", help="Keep ports without a known service (default: drop).")
    ap.add_argument("--dry-run", action="store_true", help="Do not write files; only report changes.")
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    port_map_path = Path(args.port_map)
    if not port_map_path.exists():
        raise SystemExit(f"Port map not found: {port_map_path}")

    if not args.in_place and not args.outdir:
        raise SystemExit("Either use --in-place or provide --outdir.")

    outdir = Path(args.outdir) if args.outdir else parsed_dir
    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)

    rules = load_port_rules(port_map_path)

    for path in sorted(parsed_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue

        changed = False
        for app, endpoints in data.items():
            if not isinstance(endpoints, dict):
                continue
            for endpoint, values in endpoints.items():
                if not isinstance(values, dict):
                    continue
                if "ports" not in values or not isinstance(values["ports"], list):
                    continue

                old_ports = list(values["ports"])
                new_ports = annotate_ports(old_ports, rules, keep_unknown=args.keep_unknown)

                if old_ports != new_ports:
                    values["ports"] = new_ports
                    changed = True

        if changed:
            out_path = path if args.in_place else (outdir / path.name)
            if args.dry_run:
                print(f"[dry-run] would update: {path.name}")
            else:
                out_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
                print(f"Updated: {out_path}")

    print("Done.")


if __name__ == "__main__":
    main()
