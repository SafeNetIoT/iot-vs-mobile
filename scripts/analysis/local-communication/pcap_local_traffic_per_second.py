#!/usr/bin/env python3
"""
Extract local (LAN-to-LAN) IPv4 traffic from PCAPs and aggregate bytes per second.

Local traffic is defined as packets where both src and dst are RFC1918 addresses:
10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.

Supports two directory layouts:
1) "monitor" layout: <base>/moniotr/<device>/<experiment>/*.pcap
2) "pcapdroid" layout: <base>/PCAPdroid/*.pcap

Outputs a JSON mapping:
{ "<device>": { "<second>": <bytes>, ... }, ... }
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict

import pyshark

# FIX: RuntimeError: This event loop is already running (common in notebooks)
try:
    import nest_asyncio  # type: ignore
    nest_asyncio.apply()
except Exception:
    pass


SECONDS_TO_BYTES = Dict[int, int]
DEVICE_TO_SECONDS = Dict[str, SECONDS_TO_BYTES]


def is_rfc1918_ipv4(ip: str) -> bool:
    """Return True if ip is RFC1918 private IPv4."""
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    # 172.16.0.0/12
    return any(ip.startswith(f"172.{i}.") for i in range(16, 32))


def accumulate_local_bytes_from_pcap(pcap_path: Path) -> SECONDS_TO_BYTES:
    """
    Parse a pcap and aggregate bytes per second for packets where both src and dst are local.
    Uses packet.frame_info.time_relative (seconds from capture start).
    """
    per_second: SECONDS_TO_BYTES = {}

    cap = pyshark.FileCapture(str(pcap_path), keep_packets=False)
    try:
        for pkt in cap:
            if "IP" not in pkt:
                continue

            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst

            if not (is_rfc1918_ipv4(src_ip) and is_rfc1918_ipv4(dst_ip)):
                continue

            t = float(pkt.frame_info.time_relative)
            sec = int(t)
            length = int(pkt.length)

            per_second[sec] = per_second.get(sec, 0) + length
    finally:
        # Ensure tshark process is terminated
        cap.close()

    return per_second


def device_name_from_pcapdroid(filename: str) -> str:
    """
    Infer device name from PCAPdroid filenames:
      - *_nofrida.pcap -> strip suffix and trailing token
      - *.pcap        -> strip extension and trailing token
    """
    if filename.endswith("_nofrida.pcap"):
        stem = filename.replace("_nofrida.pcap", "")
    elif filename.endswith(".pcap"):
        stem = filename[:-5]
    else:
        stem = filename

    parts = stem.split("_")
    # Original logic: drop the last underscore-separated token
    return "_".join(parts[:-1]) if len(parts) > 1 else stem


def collect_from_monitor_layout(base: Path) -> DEVICE_TO_SECONDS:
    """
    Layout:
      base/moniotr/<device>/<experiment>/*.pcap
    """
    root = base / "moniotr"
    out: DEVICE_TO_SECONDS = {}

    for device_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        device = device_dir.name
        out[device] = {}

        print(f"Analyzing device: {device}")
        for exp_dir in sorted(p for p in device_dir.iterdir() if p.is_dir()):
            for pcap in sorted(exp_dir.glob("*.pcap")):
                print(f"  PCAP: {pcap.name}")
                try:
                    per_sec = accumulate_local_bytes_from_pcap(pcap)
                    for sec, b in per_sec.items():
                        out[device][sec] = out[device].get(sec, 0) + b
                except Exception as e:
                    print(f"  Error analyzing {pcap}: {e}")

    return out


def collect_from_pcapdroid_layout(base: Path) -> DEVICE_TO_SECONDS:
    """
    Layout:
      base/PCAPdroid/*.pcap
    """
    root = base / "PCAPdroid"
    out: DEVICE_TO_SECONDS = {}

    for pcap in sorted(root.glob("*.pcap")):
        device = device_name_from_pcapdroid(pcap.name)
        out.setdefault(device, {})

        print(f"Analyzing: {pcap.name} (device={device})")
        try:
            per_sec = accumulate_local_bytes_from_pcap(pcap)
            for sec, b in per_sec.items():
                out[device][sec] = out[device].get(sec, 0) + b
        except Exception as e:
            print(f"Error analyzing {pcap}: {e}")

    return out


def sort_nested_seconds(data: DEVICE_TO_SECONDS) -> DEVICE_TO_SECONDS:
    """Sort second keys for stable JSON output."""
    return {dev: {sec: data[dev][sec] for sec in sorted(data[dev])} for dev in data}


def main() -> None:
    p = argparse.ArgumentParser(
        description="Aggregate local (LAN-to-LAN) IPv4 bytes per second from PCAPs."
    )
    p.add_argument("experiment_name", help="Experiment name")
    p.add_argument("frida", help="frida or nofrida (folder level)")
    p.add_argument("month", help="Month folder level (e.g., 2024-01)")
    p.add_argument(
        "--monitor",
        action="store_true",
        help="Use monitor layout (base/moniotr/<device>/<experiment>/*.pcap). Default: PCAPdroid layout.",
    )
    p.add_argument(
        "--base-root",
        required=True,
        help="Root directory containing experiments.",
    )
    args = p.parse_args()

    base = Path(args.base_root) / args.experiment_name / args.frida / args.month
    if not base.exists():
        raise SystemExit(f"Base folder not found: {base}")

    if args.monitor:
        traffic = collect_from_monitor_layout(base)
        out_path = base / f"local_communication_monitor_{args.frida}_{args.month}.json"
    else:
        traffic = collect_from_pcapdroid_layout(base)
        out_path = base / f"local_communication_pcapdroid_{args.frida}_{args.month}.json"

    traffic_sorted = sort_nested_seconds(traffic)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(traffic_sorted, f)

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
