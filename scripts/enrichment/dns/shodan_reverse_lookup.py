#!/usr/bin/env python3
"""
Reverse-lookup hostnames for IPs via the Shodan API.

Input:
  - JSON list of IPs, e.g., ["1.2.3.4"]
  - JSON dictionary whose keys are IPs

Output:
  - JSON dictionary mapping each IP to hostnames or null

Authentication:
  export SHODAN_API_KEY="<your-key>"

Do not store API keys in source files or commit them to the repository.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional, Union

import shodan


def load_ips(path: Path) -> List[str]:
    data: Union[List[Any], Dict[str, Any]]
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict):
        return [str(k) for k in data.keys()]

    raise ValueError("Input JSON must be a list of IPs or a dict keyed by IPs.")


def main() -> None:
    p = argparse.ArgumentParser(description="Shodan reverse lookup for IP hostnames.")
    p.add_argument("--input", required=True, help="Path to JSON file containing IPs (list) or dict keyed by IPs.")
    p.add_argument("--output", required=True, help="Path to output JSON mapping IP -> hostnames/null.")
    p.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between queries (default: 1.0).")
    args = p.parse_args()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("Set the SHODAN_API_KEY environment variable.")

    in_path = Path(args.input)
    out_path = Path(args.output)
    ips = load_ips(in_path)

    api = shodan.Shodan(api_key)
    ip_to_hostnames: Dict[str, Optional[List[str]]] = {}

    for ip in ips:
        print(f"Analyzing IP: {ip}")
        try:
            # host() returns services; hostnames often appear in each service record
            res = api.host(ip)
            hostnames: List[str] = []
            for item in res.get("data", []):
                hostnames.extend(item.get("hostnames", []) or [])
            # de-duplicate, keep order
            seen = set()
            hostnames_unique = [h for h in hostnames if not (h in seen or seen.add(h))]
            ip_to_hostnames[ip] = hostnames_unique if hostnames_unique else None
            if ip_to_hostnames[ip]:
                print(f"  Found: {ip_to_hostnames[ip]}")
        except shodan.APIError as e:
            print(f"  Shodan APIError for {ip}: {e}")
            ip_to_hostnames[ip] = None
        except Exception as e:
            print(f"  Error for {ip}: {e}")
            ip_to_hostnames[ip] = None

        sleep(args.sleep)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(ip_to_hostnames, f, indent=2, sort_keys=True)

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
