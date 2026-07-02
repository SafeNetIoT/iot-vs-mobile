#!/usr/bin/env python3
"""
resolve_missing_providers_ipinfo.py

Resolve missing provider labels (provider == None) by looking up endpoint IPs via ipinfo.

Input:
  - Folder of parsed traffic JSON files (default: ./parsed_files/)
  - Only files matching a token (default: "same")

Output:
  - JSON mapping: { "<ip>": "<org>", ... }

Security:
  Provide your token via env var IPINFO_TOKEN.

Example:
  export IPINFO_TOKEN="..."
  python resolve_missing_providers_ipinfo.py \
    --parsed-dir ./parsed_files \
    --match-token same \
    --out missing_providers_same.json \
    --sleep 0.5
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Dict

import ipinfo


RFC1918_PREFIXES = (
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_local_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918_PREFIXES)


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict at top-level in {path}, got {type(data).__name__}")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description="Resolve missing provider labels via ipinfo.")
    ap.add_argument("--parsed-dir", default="./parsed_files", help="Folder with parsed traffic JSON files.")
    ap.add_argument("--match-token", default="same", help="Only process filenames containing this token.")
    ap.add_argument("--out", default="missing_providers.json", help="Output JSON mapping ip->org.")
    ap.add_argument("--sleep", type=float, default=0.5, help="Seconds to sleep between ipinfo requests.")
    args = ap.parse_args()
    
    api_key = os.getenv("IPINFO_TOKEN")
    if not api_key:
        raise SystemExit("Set the IPINFO_TOKEN environment variable.")

    parsed_dir = Path(args.parsed_dir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    handler = ipinfo.getHandler(api_key)

    ip_to_org: Dict[str, str] = {}
    looked_up = 0

    for path in sorted(parsed_dir.glob("*.json")):
        if args.match_token and args.match_token not in path.name:
            continue

        traffic = load_json(path)
        for _name, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue

            for _endpoint, values in endpoints.items():
                if not isinstance(values, dict):
                    continue
                if values.get("provider") is not None:
                    continue

                for ip in values.get("IPs", []) or []:
                    ip = str(ip)
                    if is_local_ip(ip) or ip in ip_to_org:
                        continue

                    print(f"Query ipinfo: {ip}")
                    try:
                        details = handler.getDetails(ip)
                        org = details.all.get("org")
                        if org:
                            ip_to_org[ip] = str(org)
                            print(f"  -> {org}")
                        looked_up += 1
                    except Exception as e:
                        print(f"  error: {e}")

                    time.sleep(args.sleep)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(ip_to_org, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote: {out_path} (resolved {len(ip_to_org)} IPs; looked up {looked_up} IPs)")


if __name__ == "__main__":
    main()
