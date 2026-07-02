#!/usr/bin/env python3
"""
summarize_country_distribution.py

Summarize endpoint country distribution from parsed traffic JSON files.

What it does:
  - Scans parsed traffic JSON files in a folder (default: ../parsed_files/)
  - Skips RFC1918 local IP endpoints (optional, default: skip)
  - Aggregates by country for each layout (moniotr / pcapdroid):
      * metric=endpoints: counts unique endpoints per country
      * metric=bytes: sums bytes (from packet_sizes) per country

Expected parsed traffic format:
  {
    "<app>": {
      "<endpoint>": {
        "country": "US",
        "packet_sizes": {"file1.pcap":[...], ...},
        ...
      },
      ...
    },
    ...
  }

Examples:
  # Count unique endpoints per country (same/different inferred by filename token)
  python summarize_country_distribution.py --parsed-dir ../parsed_files --experiment different --metric endpoints

  # Sum bytes per country
  python summarize_country_distribution.py --parsed-dir ../parsed_files --experiment different --metric bytes

Outputs (written to --outdir, default: .):
  - countries_moniotr_<experiment>.json   or bytes_countries_moniotr_<experiment>.json
  - countries_pcapdroid_<experiment>.json or bytes_countries_pcapdroid_<experiment>.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Set


RFC1918_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_local_ip(s: str) -> bool:
    return any(s.startswith(p) for p in RFC1918_PREFIXES)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def add_bytes(country_totals: Dict[str, int], country: str, packet_sizes: Any) -> None:
    if not country:
        return
    country_totals.setdefault(country, 0)
    if not isinstance(packet_sizes, dict):
        return
    for _fname, sizes in packet_sizes.items():
        if not isinstance(sizes, list):
            continue
        for s in sizes:
            try:
                country_totals[country] += int(s)
            except Exception:
                continue


def add_endpoint(
    endpoint_sets: Dict[str, Set[str]],
    country_counts: Dict[str, int],
    country: str,
    endpoint: str,
) -> None:
    if not country:
        return
    endpoint_sets.setdefault(country, set())
    if endpoint in endpoint_sets[country]:
        return
    endpoint_sets[country].add(endpoint)
    country_counts[country] = country_counts.get(country, 0) + 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize country distribution (unique endpoints or bytes).")
    ap.add_argument("--parsed-dir", default="../parsed_files", help="Directory containing parsed traffic JSON files.")
    ap.add_argument("--experiment", default="different", help="Filename token to match (e.g., same/different).")
    ap.add_argument("--metric", choices=["endpoints", "bytes"], default="bytes", help="Aggregate metric.")
    ap.add_argument("--outdir", default=".", help="Output directory.")
    ap.add_argument(
        "--include-local",
        action="store_true",
        help="Include RFC1918 endpoints in country stats (default: skip local endpoints).",
    )
    args = ap.parse_args()

    parsed_dir = Path(args.parsed_dir)
    outdir = Path(args.outdir)
    if not parsed_dir.is_dir():
        raise SystemExit(f"Parsed dir not found: {parsed_dir}")

    # Results per layout
    countries_moniotr: Dict[str, int] = {}
    countries_pcapdroid: Dict[str, int] = {}

    # Only needed for endpoints metric (to avoid counting same endpoint twice)
    seen_moniotr: Dict[str, Set[str]] = {}
    seen_pcapdroid: Dict[str, Set[str]] = {}

    for path in sorted(parsed_dir.glob("*.json")):
        name = path.name
        if args.experiment not in name:
            continue

        is_moniotr = "moniotr" in name
        is_pcapdroid = "pcapdroid" in name
        if not (is_moniotr or is_pcapdroid):
            continue

        traffic = load_json(path)
        if not isinstance(traffic, dict):
            continue

        for _app, endpoints in traffic.items():
            if not isinstance(endpoints, dict):
                continue

            for endpoint, values in endpoints.items():
                endpoint = str(endpoint)
                if (not args.include_local) and is_local_ip(endpoint):
                    continue
                if not isinstance(values, dict):
                    continue

                country = values.get("country")
                if country is None:
                    continue
                country = str(country)

                if args.metric == "bytes":
                    pkt_sizes = values.get("packet_sizes", {})
                    if is_moniotr:
                        add_bytes(countries_moniotr, country, pkt_sizes)
                    else:
                        add_bytes(countries_pcapdroid, country, pkt_sizes)
                else:  # endpoints
                    if is_moniotr:
                        add_endpoint(seen_moniotr, countries_moniotr, country, endpoint)
                    else:
                        add_endpoint(seen_pcapdroid, countries_pcapdroid, country, endpoint)

    # Sort outputs descending by value
    countries_moniotr_sorted = dict(sorted(countries_moniotr.items(), key=lambda kv: kv[1], reverse=True))
    countries_pcapdroid_sorted = dict(sorted(countries_pcapdroid.items(), key=lambda kv: kv[1], reverse=True))

    prefix = "bytes_countries" if args.metric == "bytes" else "countries"
    out_m = outdir / f"{prefix}_moniotr_{args.experiment}.json"
    out_p = outdir / f"{prefix}_pcapdroid_{args.experiment}.json"

    save_json(out_m, countries_moniotr_sorted)
    save_json(out_p, countries_pcapdroid_sorted)

    print(f"Wrote: {out_m}")
    print(f"Wrote: {out_p}")


if __name__ == "__main__":
    main()
