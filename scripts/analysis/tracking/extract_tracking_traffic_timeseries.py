#!/usr/bin/env python3
"""
extract_tracking_traffic_timeseries.py

Extract per-second bytes sent to Tracking & Analytics endpoints from PCAPs.

Inputs:
  - Parsed endpoints JSON (used to identify tracking endpoints and their IPs)
  - PCAP folder (moniotr layout or PCAPdroid layout)

Output:
  - JSON: { device: { endpoint: { second: bytes, ... }, ... }, ... }

Example (moniotr):
  python extract_tracking_traffic_timeseries.py \
    --pcap-root /path/to/experiment/different_network_experiments/no_frida/jan2024/moniotr \
    --parsed /path/to/experiment/different_network_experiments/no_frida/jan2024/moniotr_no_frida_jan2024.json \
    --out tracking_moniotr_no_frida_jan2024.json

Example (pcapdroid):
  python extract_tracking_traffic_timeseries.py \
    --pcap-root /path/to/experiment/different_network_experiments/no_frida/jan2024/PCAPdroid \
    --parsed /path/to/experiment/different_network_experiments/no_frida/jan2024/pcapdroid_no_frida_jan2024.json \
    --name-map /path/to/experiment/moniotr_pcapdroid_names.json \
    --out tracking_pcapdroid_no_frida_jan2024.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pyshark

try:
    import nest_asyncio  # type: ignore
    nest_asyncio.apply()
except Exception:
    pass


TRACKING_LABEL = "analytics_and_trackers"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def tracking_filter_for_device(device: str, parsed: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    ip_list = []
    ip_to_endpoint: Dict[str, str] = {}

    endpoints = parsed.get(device, {})
    if not isinstance(endpoints, dict):
        return "", {}

    for endpoint, values in endpoints.items():
        if not isinstance(values, dict):
            continue
        if values.get("categorization") != TRACKING_LABEL:
            continue
        for ip in values.get("IPs", []) or []:
            ip_list.append(str(ip))
            ip_to_endpoint[str(ip)] = str(endpoint)

    if not ip_list:
        return "", {}

    display_filter = " || ".join([f"ip.addr == {ip}" for ip in sorted(set(ip_list))])
    return display_filter, ip_to_endpoint


def device_from_pcapdroid(filename: str) -> str:
    if filename.endswith("_nofrida.pcap"):
        stem = filename.replace("_nofrida.pcap", "")
    else:
        stem = filename.replace(".pcap", "")
    parts = stem.split("_")
    return "_".join(parts[:-1]) if len(parts) > 1 else stem


def process_pcap(pcap_path: Path, display_filter: str, ip_to_endpoint: Dict[str, str]) -> Dict[str, Dict[int, int]]:
    out: Dict[str, Dict[int, int]] = {}
    cap = pyshark.FileCapture(str(pcap_path), display_filter=display_filter, keep_packets=False)
    try:
        for pkt in cap:
            if "IP" not in pkt:
                continue
            src = str(pkt.ip.src)
            dst = str(pkt.ip.dst)

            endpoint = ip_to_endpoint.get(src) or ip_to_endpoint.get(dst)
            if not endpoint:
                continue

            sec = int(float(pkt.frame_info.time_relative))
            length = int(pkt.length)

            out.setdefault(endpoint, {})
            out[endpoint][sec] = out[endpoint].get(sec, 0) + length
    finally:
        cap.close()
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract tracking bytes-per-second per endpoint from PCAPs.")
    ap.add_argument("--pcap-root", required=True, help="PCAP root folder (moniotr/ or PCAPdroid/).")
    ap.add_argument("--parsed", required=True, help="Parsed endpoints JSON (used for tracking IPs).")
    ap.add_argument("--out", required=True, help="Output JSON path.")
    ap.add_argument("--name-map", default=None, help="Optional pcapdroid->moniotr device name map JSON.")
    ap.add_argument("--layout", choices=["moniotr", "pcapdroid"], required=True, help="Input layout.")
    args = ap.parse_args()

    parsed = load_json(Path(args.parsed))
    name_map = load_json(Path(args.name_map)) if args.name_map else {}

    pcap_root = Path(args.pcap_root)
    tracking: Dict[str, Dict[str, Dict[int, int]]] = {}

    if args.layout == "moniotr":
        for device in sorted(p for p in pcap_root.iterdir() if p.is_dir()):
            dev = device.name
            display_filter, ip_to_endpoint = tracking_filter_for_device(dev, parsed)
            tracking[dev] = {}
            if not display_filter:
                continue

            for exp in sorted(p for p in device.iterdir() if p.is_dir()):
                for pcap in sorted(exp.glob("*.pcap")):
                    per_pcap = process_pcap(pcap, display_filter, ip_to_endpoint)
                    for endpoint, series in per_pcap.items():
                        tracking[dev].setdefault(endpoint, {})
                        for sec, b in series.items():
                            tracking[dev][endpoint][sec] = tracking[dev][endpoint].get(sec, 0) + b

    else:  # pcapdroid
        for pcap in sorted(pcap_root.glob("*.pcap")):
            raw = device_from_pcapdroid(pcap.name)
            dev = name_map.get(raw, raw)

            display_filter, ip_to_endpoint = tracking_filter_for_device(dev, parsed)
            tracking.setdefault(dev, {})
            if not display_filter:
                continue

            per_pcap = process_pcap(pcap, display_filter, ip_to_endpoint)
            for endpoint, series in per_pcap.items():
                tracking[dev].setdefault(endpoint, {})
                for sec, b in series.items():
                    tracking[dev][endpoint][sec] = tracking[dev][endpoint].get(sec, 0) + b

    Path(args.out).write_text(json.dumps(tracking, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
