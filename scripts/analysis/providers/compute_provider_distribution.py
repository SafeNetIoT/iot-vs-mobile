#!/usr/bin/env python3
"""
compute_provider_distribution.py

Compute provider adoption distributions (apps vs devices) from parsed traffic JSON files,
optionally enriching missing provider labels.

What it does:
  1) Reads parsed traffic JSON files (default: ./parsed_files/*.json)
     Expected format:
       { "<app_or_device>": { "<endpoint>": {"provider": str|None, "IPs":[...], ...}, ... }, ... }

  2) Optionally fills missing providers in two ways:
     (a) IP->provider mapping JSON (e.g., produced by your ipinfo script)
     (b) IP-range inference for major cloud/CDN providers (AWS/Google/Azure/IBM/Oracle/...),
         using range files in ip_ranges_cloud_providers/.

  3) Computes, for each provider:
     - how many distinct apps contacted >=1 endpoint hosted by that provider
     - how many distinct devices contacted >=1 endpoint hosted by that provider
     - combined distribution

Outputs:
  - providers_distribution.json
  - apps_providers_distribution.json
  - devices_providers_distribution.json

Example:
  # Just compute distributions from existing 'provider' fields
  python compute_provider_distribution.py --parsed-dir ./parsed_files --match-token different

  # Also fill missing providers from an IP->org map (does NOT rewrite input files unless --write-updated)
  python compute_provider_distribution.py \
    --parsed-dir ./parsed_files --match-token different \
    --missing-providers missing_providers_same_india_usa.json

  # Additionally infer provider from IP ranges (requires netaddr and range files)
  python compute_provider_distribution.py \
    --parsed-dir ./parsed_files --match-token different \
    --missing-providers missing_providers_same_india_usa.json \
    --ip-ranges-dir ip_ranges_cloud_providers \
    --infer-from-ip-ranges

  # Rewrite parsed files with updated provider fields
  python compute_provider_distribution.py \
    --parsed-dir ./parsed_files --match-token different \
    --missing-providers missing_providers_same_india_usa.json \
    --write-updated
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple

try:
    from netaddr import IPAddress, IPNetwork
except Exception:
    IPAddress = None
    IPNetwork = None


# ----------------------------
# Helpers: JSON I/O
# ----------------------------
def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


# ----------------------------
# Provider inference via IP ranges (optional)
# ----------------------------
def ip_in_any(ip: str, cidrs: Iterable[str]) -> bool:
    if IPAddress is None or IPNetwork is None:
        raise RuntimeError("netaddr is required for --infer-from-ip-ranges")
    ip_obj = IPAddress(ip)
    for c in cidrs:
        try:
            if ip_obj in IPNetwork(c):
                return True
        except Exception:
            continue
    return False


def load_ranges(ip_ranges_dir: Path) -> Dict[str, Any]:
    """
    Load provider range files similar to your commented-out code.
    Expected filenames (if present):
      alibaba.json, aws.json, azure.json, google.json, google-cloud.json,
      ibm.json, oracle.json, akamai.json, digitalocean.csv
    """
    ranges: Dict[str, Any] = {}

    def p(name: str) -> Path:
        return ip_ranges_dir / name

    if p("aws.json").exists():
        ranges["aws"] = load_json(p("aws.json"))
    if p("google.json").exists():
        ranges["google"] = load_json(p("google.json"))
    if p("google-cloud.json").exists():
        ranges["google_cloud"] = load_json(p("google-cloud.json"))
    if p("azure.json").exists():
        ranges["azure"] = load_json(p("azure.json"))
    if p("oracle.json").exists():
        ranges["oracle"] = load_json(p("oracle.json"))
    if p("ibm.json").exists():
        ranges["ibm"] = load_json(p("ibm.json"))
    if p("akamai.json").exists():
        ranges["akamai"] = load_json(p("akamai.json"))
    if p("alibaba.json").exists():
        ranges["alibaba"] = load_json(p("alibaba.json"))

    if p("digitalocean.csv").exists():
        with p("digitalocean.csv").open("r", encoding="utf-8", newline="") as f:
            ranges["digitalocean"] = list(csv.reader(f))

    return ranges


def infer_provider_from_ranges(ip: str, ranges: Dict[str, Any]) -> Optional[str]:
    """
    Mirrors your commented-out check_new_providers() logic, but robustly.
    """
    if not ranges:
        return None

    # AWS
    aws = ranges.get("aws")
    if aws:
        for r in aws.get("prefixes", []):
            if ip_in_any(ip, [r.get("ip_prefix", "")]):
                return "aws"

    # Google (both)
    for key in ("google", "google_cloud"):
        g = ranges.get(key)
        if g:
            for r in g.get("prefixes", []):
                cidr = r.get("ipv4Prefix") or r.get("ip_prefix") or ""
                if cidr and ip_in_any(ip, [cidr]):
                    return "google"

    # Oracle
    oracle = ranges.get("oracle")
    if oracle:
        cidrs = []
        for region in oracle.get("regions", []):
            for c in region.get("cidrs", []):
                if "cidr" in c:
                    cidrs.append(c["cidr"])
        if cidrs and ip_in_any(ip, cidrs):
            return "oracle"

    # DigitalOcean
    do = ranges.get("digitalocean")
    if do:
        cidrs = [row[0] for row in do if row and row[0]]
        if cidrs and ip_in_any(ip, cidrs):
            return "digitalocean"

    # IBM
    ibm = ranges.get("ibm")
    if ibm:
        cidrs = []
        for dc in ibm.get("data_centers", []):
            for _k, v in (dc or {}).items():
                if isinstance(v, list):
                    for item in v:
                        for c in item.get("cidr_blocks", []) if isinstance(item, dict) else []:
                            cidrs.append(c)
        if cidrs and ip_in_any(ip, cidrs):
            return "ibm"

    # Akamai / Alibaba (generic CIDR list)
    for prov in ("akamai", "alibaba"):
        pj = ranges.get(prov)
        if pj:
            cidrs = pj if isinstance(pj, list) else pj.get("cidrs", [])
            if cidrs and ip_in_any(ip, cidrs):
                return prov

    # Azure
    az = ranges.get("azure")
    if az:
        cidrs = []
        for item in az.get("values", []):
            for c in item.get("properties", {}).get("addressPrefixes", []):
                cidrs.append(c)
        if cidrs and ip_in_any(ip, cidrs):
            return "azure"

    return None


# ----------------------------
# Core: fill providers + compute distributions
# ----------------------------
def add_adoption(dist: Dict[str, Set[str]], name: str, endpoints: Dict[str, Any]) -> None:
    for _endpoint, values in endpoints.items():
        if not isinstance(values, dict):
            continue
        provider = values.get("provider")
        if not provider:
            continue
        dist.setdefault(str(provider), set()).add(str(name))


def to_sorted_counts(dist: Dict[str, Set[str]]) -> Dict[str, int]:
    counts = {p: len(names) for p, names in dist.items()}
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def maybe_fill_provider(
    values: Dict[str, Any],
    missing_map: Dict[str, str],
    infer_ranges: bool,
    ranges: Dict[str, Any],
) -> bool:
    """
    If provider is missing, try to fill it using:
      - IP->provider map
      - IP range inference
    Returns True if provider was updated.
    """
    if values.get("provider") is not None:
        return False

    ips = values.get("IPs") or []
    for ip in ips:
        ip = str(ip)
        if ip in missing_map:
            values["provider"] = missing_map[ip]
            return True
        if infer_ranges:
            newp = infer_provider_from_ranges(ip, ranges)
            if newp:
                values["provider"] = newp
                return True

    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute provider distributions; optionally fill missing providers.")
    ap.add_argument("--parsed-dir", default="./parsed_files", help="Folder containing parsed traffic JSON files.")
    ap.add_argument("--match-token", default="different", help="Only process filenames containing this token.")
    ap.add_argument("--outdir", default=".", help="Output directory for distribution JSON files.")
    ap.add_argument(
        "--missing-providers",
        default=None,
        help="Optional JSON mapping IP->provider/org to fill provider==None.",
    )
    ap.add_argument(
        "--infer-from-ip-ranges",
        action="store_true",
        help="Infer provider from IP ranges (requires netaddr + range files).",
    )
    ap.add_argument(
        "--ip-ranges-dir",
        default="ip_ranges_cloud_providers",
        help="Directory containing provider IP range files.",
    )
    ap.add_argument(
        "--write-updated",
        action="store_true",
        help="Rewrite parsed files with updated provider fields (in place).",
    )
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    outdir = Path(args.outdir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    missing_map: Dict[str, str] = {}
    if args.missing_providers:
        mp = load_json(Path(args.missing_providers))
        if not isinstance(mp, dict):
            raise SystemExit("Missing-providers JSON must be a dict: {ip: provider}")
        missing_map = {str(k): str(v) for k, v in mp.items()}

    ranges: Dict[str, Any] = {}
    if args.infer_from_ip_ranges:
        ranges = load_ranges(Path(args.ip_ranges_dir))

    overall: Dict[str, Set[str]] = {}
    apps: Dict[str, Set[str]] = {}
    devices: Dict[str, Set[str]] = {}

    updated_files = 0
    updated_endpoints = 0

    for path in sorted(parsed_dir.glob("*.json")):
        if args.match_token and args.match_token not in path.name:
            continue

        data = load_json(path)
        if not isinstance(data, dict):
            continue

        is_device_file = "moniotr" in path.name

        # Optionally fill missing providers
        changed = False
        for name, endpoints in data.items():
            if not isinstance(endpoints, dict):
                continue
            for _endpoint, values in endpoints.items():
                if not isinstance(values, dict):
                    continue
                if maybe_fill_provider(values, missing_map, args.infer_from_ip_ranges, ranges):
                    changed = True
                    updated_endpoints += 1

            # Add adoption stats after possible filling
            add_adoption(overall, name, endpoints)
            if is_device_file:
                add_adoption(devices, name, endpoints)
            else:
                add_adoption(apps, name, endpoints)

        if changed and args.write_updated:
            save_json(path, data)
            updated_files += 1

    outdir.mkdir(parents=True, exist_ok=True)
    save_json(outdir / "providers_distribution.json", to_sorted_counts(overall))
    save_json(outdir / "apps_providers_distribution.json", to_sorted_counts(apps))
    save_json(outdir / "devices_providers_distribution.json", to_sorted_counts(devices))

    print(f"Wrote: {outdir / 'providers_distribution.json'}")
    print(f"Wrote: {outdir / 'apps_providers_distribution.json'}")
    print(f"Wrote: {outdir / 'devices_providers_distribution.json'}")
    if args.missing_providers or args.infer_from_ip_ranges:
        print(f"Filled provider for {updated_endpoints} endpoint entries.")
    if args.write_updated:
        print(f"Updated {updated_files} file(s) in place.")


if __name__ == "__main__":
    main()
