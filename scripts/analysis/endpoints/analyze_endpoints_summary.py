#!/usr/bin/env python3
"""
analyze_endpoints_summary.py

Summarize endpoints and endpoint categories from two parsed-traffic JSON files
(e.g., frida vs no-frida).

Input format (per file):
  { "<app>": { "<endpoint>": {"categorization": "...", ...}, ... }, ... }

Outputs:
  - JSON summary (counts, per-app stats, category distributions)
  - optional text output on stdout

Example:
  python analyze_endpoints_summary.py \
    --frida ./parsed_files/usa_pcapdroid_frida_feb2024.json \
    --nofrida ./parsed_files/usa_pcapdroid_no_frida_feb2024.json \
    --out summary_usa_pcapdroid_feb2024.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Dict, List, Set

try:
    from IPy import IP  # matches your original dependency
except Exception:
    IP = None

RFC1918_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

MULTICAST_RE = re.compile(
    r"^(22[4-9]|23[0-9])\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

DEFAULT_EXCLUDED = ["ring_doorbell", "coffee_maker_lavazza", "cosori_air_fryer", "cosori_airfrier"]
DEFAULT_ONLY_SAME = ["chromecast", "sonos_speaker", "bose_speaker", "google_nest_hub"]


def is_local_ip(s: str) -> bool:
    return any(s.startswith(p) for p in RFC1918_PREFIXES)


def is_multicast_ip(s: str) -> bool:
    return bool(MULTICAST_RE.match(s))


def is_ipv4_literal(s: str) -> bool:
    if IP is None:
        return False
    try:
        IP(s)
        return True
    except Exception:
        return False


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def add_counts(
    traffic: Dict[str, Any],
    excluded_apps: Set[str],
    total_endpoints: Set[str],
    endpoints_per_app: Dict[str, int],
    categories_total: Dict[str, int],
    categories_per_app: Dict[str, Dict[str, int]],
    local_ips: Set[str],
    multicast_ips: Set[str],
    unsolved_ips: Set[str],
) -> None:
    for app, endpoints in traffic.items():
        if app in excluded_apps or not isinstance(endpoints, dict):
            continue

        for endpoint, values in endpoints.items():
            endpoint = str(endpoint)

            if is_local_ip(endpoint):
                local_ips.add(endpoint)
            elif is_multicast_ip(endpoint):
                multicast_ips.add(endpoint)
            elif is_ipv4_literal(endpoint):
                unsolved_ips.add(endpoint)

            endpoints_per_app[app] = endpoints_per_app.get(app, 0) + 1

            if endpoint not in total_endpoints:
                total_endpoints.add(endpoint)

                cat = None
                if isinstance(values, dict):
                    cat = values.get("categorization")
                if cat is None:
                    cat = "unknown"

                categories_total[cat] = categories_total.get(cat, 0) + 1

            categories_per_app.setdefault(app, {})
            cat = values.get("categorization") if isinstance(values, dict) else None
            if cat is None:
                cat = "unknown"
            categories_per_app[app][cat] = categories_per_app[app].get(cat, 0) + 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize endpoints/categories from frida + no-frida parsed traffic JSON.")
    ap.add_argument("--frida", required=True, help="Path to frida parsed JSON.")
    ap.add_argument("--nofrida", required=True, help="Path to no-frida parsed JSON.")
    ap.add_argument("--out", required=True, help="Output JSON summary path.")
    ap.add_argument("--exclude-apps", nargs="*", default=DEFAULT_EXCLUDED, help="Apps/devices to exclude.")
    ap.add_argument("--only-same", nargs="*", default=DEFAULT_ONLY_SAME, help="Apps expected to appear only in SAME runs.")
    ap.add_argument("--print", action="store_true", help="Print brief summary to stdout.")
    args = ap.parse_args()

    frida = load_json(Path(args.frida))
    nofrida = load_json(Path(args.nofrida))

    excluded = set(args.exclude_apps)

    total_endpoints: Set[str] = set()
    endpoints_per_app: Dict[str, int] = {}
    categories_total: Dict[str, int] = {}
    categories_per_app: Dict[str, Dict[str, int]] = {}
    local_ips: Set[str] = set()
    multicast_ips: Set[str] = set()
    unsolved_ips: Set[str] = set()

    add_counts(frida, excluded, total_endpoints, endpoints_per_app, categories_total, categories_per_app,
               local_ips, multicast_ips, unsolved_ips)
    add_counts(nofrida, excluded, total_endpoints, endpoints_per_app, categories_total, categories_per_app,
               local_ips, multicast_ips, unsolved_ips)

    # ONLY_SAME handling: endpoints that appear exclusively in apps listed in --only-same
    only_same_apps = set(args.only_same)
    only_same_endpoints: Set[str] = set()
    endpoints_seen_outside: Set[str] = set()

    for dataset in (frida, nofrida):
        for app, endpoints in dataset.items():
            if app in excluded or not isinstance(endpoints, dict):
                continue
            for endpoint in endpoints.keys():
                endpoint = str(endpoint)
                if app in only_same_apps:
                    only_same_endpoints.add(endpoint)
                else:
                    endpoints_seen_outside.add(endpoint)

    only_same_endpoints = only_same_endpoints - endpoints_seen_outside

    counts = list(endpoints_per_app.values())
    stats = {
        "apps_counted": len(endpoints_per_app),
        "mean_endpoints_per_app": mean(counts) if counts else 0.0,
        "stdev_endpoints_per_app": stdev(counts) if len(counts) >= 2 else 0.0,
        "max_endpoints_per_app": max(counts) if counts else 0,
    }

    out = {
        "totals": {
            "unique_endpoints": len(total_endpoints),
            "local_ips": len(local_ips),
            "multicast_ips": len(multicast_ips),
            "unmatched_ip_endpoints": len(unsolved_ips),
        },
        "stats": stats,
        "endpoint_categories_total": dict(sorted(categories_total.items(), key=lambda kv: kv[1], reverse=True)),
        "endpoints_per_app": dict(sorted(endpoints_per_app.items(), key=lambda kv: kv[1], reverse=True)),
        "endpoint_categories_per_app": categories_per_app,
        "only_same_endpoints": sorted(only_same_endpoints),
        "unmatched_ip_endpoints": sorted(unsolved_ips),
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")

    if args.print:
        print(f"Unique endpoints: {out['totals']['unique_endpoints']}")
        print(f"Apps counted: {stats['apps_counted']}")
        print(f"Mean endpoints/app: {stats['mean_endpoints_per_app']:.2f}")

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
