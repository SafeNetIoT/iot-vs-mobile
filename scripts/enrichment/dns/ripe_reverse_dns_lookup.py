#!/usr/bin/env python3
"""
Augment a mapping IP -> list[str] with reverse DNS results from RIPE Stat.

Input JSON must be a dict:
  { "1.2.3.4": ["existing.example"], "5.6.7.8": [] }

Output JSON:
  same structure, with new domains appended (de-duplicated).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import sleep
from typing import Dict, List

import requests


RIPE_URL = "https://stat.ripe.net/data/reverse-dns-ip/data.json"


def main() -> None:
    p = argparse.ArgumentParser(description="RIPE Stat reverse DNS lookup for IPs.")
    p.add_argument("--input", required=True, help="Path to input JSON mapping IP -> list of domains.")
    p.add_argument("--output", required=True, help="Path to output JSON mapping IP -> list of domains (updated).")
    p.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between queries (default: 1.0).")
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout seconds (default: 15).")
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    with in_path.open("r", encoding="utf-8") as f:
        ip_map: Dict[str, List[str]] = json.load(f)

    if not isinstance(ip_map, dict):
        raise SystemExit("Input JSON must be a dict keyed by IPs: {ip: [domains...]}")

    session = requests.Session()

    for ip, known in ip_map.items():
        if not isinstance(known, list):
            ip_map[ip] = []
            known = ip_map[ip]

        print(f"Querying: {ip}")
        try:
            r = session.get(RIPE_URL, params={"resource": ip}, timeout=args.timeout)
            r.raise_for_status()
            result = r.json()
            domains = result.get("data", {}).get("result", None)

            if not domains:
                sleep(args.sleep)
                continue

            # Append only new domains
            for d in domains:
                if d and d not in known:
                    known.append(d)
                    print(f"  New domain: {ip} -> {d}")

        except requests.RequestException as e:
            print(f"  HTTP error for {ip}: {e}")
        except Exception as e:
            print(f"  Error for {ip}: {e}")

        sleep(args.sleep)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(ip_map, f, indent=2, sort_keys=True)

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
