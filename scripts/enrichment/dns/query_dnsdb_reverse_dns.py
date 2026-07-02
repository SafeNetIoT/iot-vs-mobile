#!/usr/bin/env python3
"""
query_dnsdb_reverse_dns.py

Query DNSDB (DomainTools) reverse DNS for IPs and optionally save results.

Example:
  export DNSDB_API_KEY="key"
  python query_dnsdb_reverse_dns.py --ips unsolved_ips.txt --outdir ./domaintools_reports --sleep 1.0
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from typing import List, Optional

import requests


def read_ips(path: Path) -> List[str]:
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description="DNSDB reverse DNS lookup for a list of IPs.")
    ap.add_argument("--ips", required=True, help="Text file with one IP per line.")
    ap.add_argument("--outdir", default=None, help="If set, save raw NDJSON per IP into this directory.")
    ap.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between requests.")
    args = ap.parse_args()

    api_key = os.getenv("DNSDB_API_KEY")
if not api_key:
    raise SystemExit("Set the DNSDB_API_KEY environment variable.")

    ips = read_ips(Path(args.ips))
    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    headers = {"Accept": "application/x-ndjson", "X-API-Key": api_key}

    for ip in ips:
        url = f"https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/{ip}"
        try:
            r = session.get(url, headers=headers, timeout=20)
            r.raise_for_status()
            text = r.text
            print(f"{ip}: {len(text)} bytes returned")
            if outdir:
                (outdir / f"{ip}.txt").write_text(text, encoding="utf-8")
        except Exception as e:
            print(f"{ip}: error {e}")

        time.sleep(args.sleep)


if __name__ == "__main__":
    main()
