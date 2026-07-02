#!/usr/bin/env python3
"""
count_unique_endpoints_per_provider.py

Count the number of UNIQUE endpoints per provider from parsed traffic JSON files.

Expected input format:
  { "<app>": { "<endpoint>": {"provider": "...", ...}, ... }, ... }

Example:
  python count_unique_endpoints_per_provider.py \
    --phone ../parsed-files/different_pcapdroid_no_frida_jan2024.json \
    --device ../parsed-files/different_moniotr_no_frida_jan2024.json \
    --out endpoints_per_provider.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Set


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict at top-level in {path}, got {type(data).__name__}")
    return data


def count_unique_endpoints_by_provider(traffic: Dict[str, Any]) -> Dict[str, int]:
    prov_to_eps: Dict[str, Set[str]] = {}

    for _app, endpoints in traffic.items():
        if not isinstance(endpoints, dict):
            continue
        for endpoint, values in endpoints.items():
            if not isinstance(values, dict):
                continue
            provider = values.get("provider")
            if not provider:
                continue
            prov_to_eps.setdefault(str(provider), set()).add(str(endpoint))

    return dict(sorted(((p, len(eps)) for p, eps in prov_to_eps.items()), key=lambda kv: kv[1], reverse=True))


def main() -> None:
    ap = argparse.ArgumentParser(description="Count unique endpoints per provider.")
    ap.add_argument("--phone", required=True, help="Parsed traffic JSON for phone/app side (e.g., pcapdroid).")
    ap.add_argument("--device", required=True, help="Parsed traffic JSON for device side (e.g., moniotr).")
    ap.add_argument("--out", default="endpoints_per_provider.json", help="Output JSON (default: endpoints_per_provider.json).")
    args = ap.parse_args()

    phone_path = Path(args.phone)
    device_path = Path(args.device)

    phone_counts = count_unique_endpoints_by_provider(load_json(phone_path))
    device_counts = count_unique_endpoints_by_provider(load_json(device_path))

    out = {"phone": phone_counts, "device": device_counts}

    out_path = Path(args.out)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Wrote: {out_path}")
    print(f"Phone providers: {len(phone_counts)} | Device providers: {len(device_counts)}")


if __name__ == "__main__":
    main()
