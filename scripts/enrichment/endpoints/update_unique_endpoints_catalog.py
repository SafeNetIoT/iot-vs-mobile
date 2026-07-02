#!/usr/bin/env python3
"""
update_unique_endpoints_catalog.py

Update a catalog of unique endpoints (endpoint -> categorization) using parsed traffic.

Inputs:
  - Parsed traffic JSON: {app: {endpoint: {"categorization": "...", ...}, ...}, ...}
  - Existing catalog JSON: {endpoint: category, ...}
  - Optional DNS map directory: files containing {ip: hostname, ...}

Example:
  python update_unique_endpoints_catalog.py \
    --traffic traffic.json \
    --catalog moniotr_unique_endpoints_oct2023.json \
    --dns-dir ../dns_maps_server \
    --out moniotr_unique_endpoints_oct2023.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

RFC1918_RE = re.compile(
    r"^(10(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|((172\.(1[6-9]|2\d|3[01]))|192\.168)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})$"
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def resolve_with_dns_maps(endpoint: str, dns_dir: Optional[Path]) -> str:
    if dns_dir is None:
        return endpoint
    for f in sorted(dns_dir.glob("*.json")):
        m = load_json(f)
        if isinstance(m, dict) and endpoint in m:
            return str(m[endpoint])
    return endpoint


def main() -> None:
    ap = argparse.ArgumentParser(description="Update unique endpoint catalog from parsed traffic.")
    ap.add_argument("--traffic", required=True, help="Parsed traffic JSON file.")
    ap.add_argument("--catalog", required=True, help="Existing catalog JSON (endpoint->category).")
    ap.add_argument("--dns-dir", default=None, help="Optional directory of dns maps (ip->hostname).")
    ap.add_argument("--out", required=True, help="Output catalog JSON.")
    args = ap.parse_args()

    traffic: Dict[str, Any] = load_json(Path(args.traffic))
    catalog: Dict[str, Any] = load_json(Path(args.catalog))
    dns_dir = Path(args.dns_dir) if args.dns_dir else None

    if not isinstance(catalog, dict):
        raise SystemExit("Catalog must be a JSON object: {endpoint: category}")

    added = 0
    for _app, endpoints in (traffic or {}).items():
        if not isinstance(endpoints, dict):
            continue
        for ep, analysis in endpoints.items():
            ep = resolve_with_dns_maps(str(ep), dns_dir)
            if RFC1918_RE.match(ep):
                continue
            if ep not in catalog:
                cat = analysis.get("categorization") if isinstance(analysis, dict) else "unknown"
                catalog[ep] = cat
                added += 1

    save_json(Path(args.out), catalog)
    print(f"Wrote {args.out} (added {added} endpoints; total {len(catalog)})")


if __name__ == "__main__":
    main()
