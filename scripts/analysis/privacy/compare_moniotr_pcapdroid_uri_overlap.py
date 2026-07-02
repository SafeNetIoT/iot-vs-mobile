#!/usr/bin/env python3
"""
compare_moniotr_pcapdroid_uri_overlap.py

Compare URI overlap between MonIoTr and PCAPdroid extractions for each device.

What it does:
  - Reads per-device URI JSON files from two folders:
      moniotr:  [{"uri": "...", ...}, ...]
      pcapdroid:[{"uri": "...", ...}, ...]
  - Matches URIs in two ways:
      1) exact URI match
      2) hostname match (same netloc)
  - Produces a per-device report listing the overlapping URIs seen in each source.

Expected filename convention:
  - MonIoTr files: <device>_<something>.json  -> device inferred as all tokens except last
  - PCAPdroid files: contains <device> somewhere in filename (same as your original)

Example:
  python compare_moniotr_pcapdroid_uri_overlap.py \
    --moniotr-dir uris_moniotr_usa \
    --pcapdroid-dir uris_pcapdroid_usa \
    --out usa_uri_overlap.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Set
from urllib.parse import urlparse


def load_uri_list(path: Path) -> List[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    uris: List[str] = []
    for item in data:
        if isinstance(item, dict) and "uri" in item:
            uris.append(str(item["uri"]))
    return uris


def hostname(uri: str) -> str:
    try:
        p = urlparse(uri)
        if p.netloc:
            return p.netloc
        # handle URI without scheme
        p2 = urlparse("https://" + uri)
        return p2.netloc or ""
    except Exception:
        # fallback similar to your original split logic
        parts = uri.split("/")
        return parts[2] if len(parts) > 2 else ""


def device_from_moniotr_filename(name: str) -> str:
    # original logic: '_'.join(filename.split('_')[:-1])
    parts = name.split("_")
    return "_".join(parts[:-1]) if len(parts) > 1 else name.rsplit(".", 1)[0]


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute MonIoTr/PCAPdroid URI overlap per device.")
    ap.add_argument("--moniotr-dir", required=True, help="Directory with moniotr URI JSON files.")
    ap.add_argument("--pcapdroid-dir", required=True, help="Directory with pcapdroid URI JSON files.")
    ap.add_argument("--out", default="uri_overlap.json", help="Output JSON path (default: uri_overlap.json).")
    ap.add_argument("--summary", action="store_true", help="Print summary stats to stdout.")
    args = ap.parse_args()

    moniotr_dir = Path(args.moniotr_dir)
    pcapdroid_dir = Path(args.pcapdroid_dir)
    if not moniotr_dir.is_dir():
        raise SystemExit(f"MonIoTr folder not found: {moniotr_dir}")
    if not pcapdroid_dir.is_dir():
        raise SystemExit(f"PCAPdroid folder not found: {pcapdroid_dir}")

    # Index pcapdroid files once (so we don't rescan the whole directory for each device)
    pcapdroid_files = sorted(pcapdroid_dir.glob("*.json"))

    results: Dict[str, Dict[str, List[str]]] = {}

    for moniotr_file in sorted(moniotr_dir.glob("*.json")):
        device = device_from_moniotr_filename(moniotr_file.name)

        moniotr_uris = load_uri_list(moniotr_file)
        moniotr_uri_set: Set[str] = set(moniotr_uris)
        moniotr_host_set: Set[str] = {hostname(u) for u in moniotr_uris if hostname(u)}

        # collect all pcapdroid URIs for this device across matching files
        pcap_uris: List[str] = []
        for pf in pcapdroid_files:
            if device in pf.name:
                pcap_uris.extend(load_uri_list(pf))

        pcap_uri_set: Set[str] = set(pcap_uris)
        pcap_host_set: Set[str] = {hostname(u) for u in pcap_uris if hostname(u)}

        # exact matches
        exact = moniotr_uri_set & pcap_uri_set

        # hostname matches: include any URI from each side whose hostname is shared
        shared_hosts = moniotr_host_set & pcap_host_set
        moniotr_host_matches = {u for u in moniotr_uri_set if hostname(u) in shared_hosts}
        pcap_host_matches = {u for u in pcap_uri_set if hostname(u) in shared_hosts}

        results[device] = {
            "moniotr": sorted(moniotr_host_matches | exact),
            "pcapdroid": sorted(pcap_host_matches | exact),
        }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote: {out_path}")

    if args.summary:
        devices = len(results)
        exact_total = sum(len(set(v["moniotr"]) & set(v["pcapdroid"])) for v in results.values())
        print(f"Devices: {devices}")
        print(f"Total per-device overlap (moniotr∩pcapdroid, after hostname matching): {exact_total}")


if __name__ == "__main__":
    main()
