#!/usr/bin/env python3
"""
enrich_unsolved_ips_with_domaintools.py

Use DomainTools reverse-DNS report files to suggest hostname matches for unsolved IP endpoints.

Inputs:
  --unsolved: JSON dict keyed by IP, with at least {"devices":[...]} per IP
  --endpoints: JSON dict {device: [endpoint1, endpoint2, ...]}
  --reports-dir: folder containing domaintools report text files named <ip>.txt

Outputs:
  Updates the unsolved JSON in place (or writes to --out):
    - domaintools_match: full hostname matches found in that device's endpoint list
    - domaintools_tld_match: eTLD+1 matches (registered domain) found in endpoint strings

Example:
  python enrich_unsolved_ips_with_domaintools.py \
    --unsolved same_us_india_with_extra_data.json \
    --endpoints same_india_us_endpoints_total.json \
    --reports-dir domaintools_reports \
    --out same_us_india_with_extra_data.updated.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Set

import tldextract

RRNAME_MARKER = 'rrname":"'  # matches your original parsing strategy


def parse_domaintools_report(lines: List[str]) -> Set[str]:
    domains: Set[str] = set()
    for line in lines:
        if RRNAME_MARKER in line:
            try:
                domain = line.split(RRNAME_MARKER, 1)[1].split('.","rrtype', 1)[0]
                domains.add(domain)
            except Exception:
                continue
    return domains


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Enrich unsolved IPs with DomainTools hostname matches.")
    ap.add_argument("--unsolved", required=True, help="JSON file keyed by IP (must contain devices list).")
    ap.add_argument("--endpoints", required=True, help="JSON file mapping device -> list of endpoints.")
    ap.add_argument("--reports-dir", required=True, help="Directory with DomainTools reports named <ip>.txt.")
    ap.add_argument("--out", required=True, help="Output path for updated unsolved JSON.")
    ap.add_argument("--exclude-device", nargs="*", default=["ring_doorbell"], help="Devices to exclude.")
    args = ap.parse_args()

    unsolved: Dict[str, Any] = load_json(Path(args.unsolved))
    endpoints_total: Dict[str, List[str]] = load_json(Path(args.endpoints))
    reports_dir = Path(args.reports_dir)
    excluded = set(args.exclude_device)

    for ip, meta in unsolved.items():
        if not isinstance(meta, dict) or "devices" not in meta:
            continue

        report_path = reports_dir / f"{ip}.txt"
        if not report_path.exists():
            continue

        domaintools_domains = parse_domaintools_report(report_path.read_text(encoding="utf-8", errors="replace").splitlines())
        if not domaintools_domains:
            continue

        for device in meta.get("devices", []):
            if device in excluded or device not in endpoints_total:
                continue

            device_endpoints = endpoints_total[device]

            for d in domaintools_domains:
                tld = tldextract.extract(d).registered_domain

                # full match
                if d in device_endpoints:
                    meta.setdefault("domaintools_match", [])
                    if d not in meta["domaintools_match"]:
                        meta["domaintools_match"].append(d)

                # eTLD+1 match
                if tld:
                    for ep in device_endpoints:
                        if tld in ep:
                            meta.setdefault("domaintools_tld_match", [])
                            if d not in meta["domaintools_tld_match"]:
                                meta["domaintools_tld_match"].append(d)
                            break

    save_json(Path(args.out), unsolved)
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
