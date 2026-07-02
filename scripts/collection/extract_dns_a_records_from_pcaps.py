#!/usr/bin/env python3
"""
extract_dns_a_records_from_pcaps.py

Extract DNS A-record answers from PCAPs and build per-device DNS maps (ip -> queried name).

Supports two layouts:
  - moniotr: <base>/moniotr/<device>/<experiment>/*.pcap
  - pcapdroid: <base>/PCAPdroid/*.pcap

Example (moniotr):
  python extract_dns_a_records_from_pcaps.py \
    --base /path/to/experiment/same_network_experiments/no_frida/jan2024 \
    --layout moniotr \
    --outdir dns_maps_moniotr

Example (pcapdroid):
  python extract_dns_a_records_from_pcaps.py \
    --base /path/to/experiment/same_network_experiments/no_frida/jan2024 \
    --layout pcapdroid \
    --outdir dns_maps_pcapdroid
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import pyshark

try:
    import nest_asyncio  # type: ignore
    nest_asyncio.apply()
except Exception:
    pass


def write_maps(outdir: Path, maps: Dict[str, Dict[str, str]]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, mapping in maps.items():
        (outdir / f"{name}.json").write_text(json.dumps(mapping, indent=2, sort_keys=True), encoding="utf-8")


def infer_device_from_pcapdroid(filename: str) -> str:
    if filename.endswith("_nofrida.pcap"):
        stem = filename.replace("_nofrida.pcap", "")
    elif filename.endswith(".pcap"):
        stem = filename[:-5]
    else:
        stem = filename.rsplit(".", 1)[0]
    parts = stem.split("_")
    return "_".join(parts[:-1]) if len(parts) > 1 else stem


def process_pcap(pcap: Path, mapping: Dict[str, str]) -> None:
    cap = pyshark.FileCapture(str(pcap), display_filter="dns.flags.response == 1", keep_packets=False)
    try:
        for pkt in cap:
            try:
                mapping[str(pkt.dns.a)] = str(pkt.dns.qry_name)
            except Exception:
                pass
    finally:
        cap.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract DNS A-record answers from PCAPs into per-device maps.")
    ap.add_argument("--base", required=True, help="Base folder (contains moniotr/ or PCAPdroid/).")
    ap.add_argument("--layout", choices=["moniotr", "pcapdroid"], required=True, help="Input layout.")
    ap.add_argument("--outdir", required=True, help="Output directory for per-device JSON maps.")
    args = ap.parse_args()

    base = Path(args.base)
    outdir = Path(args.outdir)
    maps: Dict[str, Dict[str, str]] = {}

    if args.layout == "moniotr":
        root = base / "moniotr"
        for dev_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            for exp_dir in sorted(p for p in dev_dir.iterdir() if p.is_dir()):
                name = f"{dev_dir.name}_{exp_dir.name}"
                maps.setdefault(name, {})
                for pcap in sorted(exp_dir.glob("*.pcap")):
                    print(f"Analyzing {pcap.name} ({name})")
                    process_pcap(pcap, maps[name])
    else:
        root = base / "PCAPdroid"
        for pcap in sorted(root.glob("*.pcap")):
            dev = infer_device_from_pcapdroid(pcap.name)
            maps.setdefault(dev, {})
            print(f"Analyzing {pcap.name} (device={dev})")
            process_pcap(pcap, maps[dev])

    write_maps(outdir, maps)
    print(f"Wrote {len(maps)} DNS map(s) to {outdir}")


if __name__ == "__main__":
    main()
