#!/usr/bin/env python3
"""
summarize_bytes_to_remote_endpoints.py

Sum bytes sent to remote (non-RFC1918) endpoints per app/device for LAN vs WAN.

It expects parsed files like:
  <experiment>_<layout>_<mode>_<month>.json
e.g.:
  same_pcapdroid_no_frida_jan2024.json
  same_moniotr_no_frida_jan2024.json
  different_pcapdroid_no_frida_jan2024.json
  different_moniotr_no_frida_jan2024.json

Output JSON:
{
  "LAN": {"devices": {...}, "apps": {...}},
  "WAN": {"devices": {...}, "apps": {...}}
}

Example:
  python summarize_bytes_to_remote_endpoints.py \
    --parsed-dir ../parsed-files \
    --month jan2024 \
    --mode no_frida \
    --out bytes_to_remote_endpoints.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


RFC1918_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_local_ip(s: str) -> bool:
    return any(s.startswith(p) for p in RFC1918_PREFIXES)


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def sum_packet_sizes(packet_sizes: Any) -> int:
    """
    packet_sizes format: { "pcap_name": [len1, len2, ...], ... }
    """
    total = 0
    if not isinstance(packet_sizes, dict):
        return 0
    for _fname, sizes in packet_sizes.items():
        if not isinstance(sizes, list):
            continue
        total += sum(int(x) for x in sizes if str(x).isdigit() or isinstance(x, int))
    return total


def accumulate_remote_bytes(parsed: Dict[str, Any]) -> Dict[str, int]:
    """
    Returns: {app_or_device: bytes_to_remote_endpoints}
    """
    out: Dict[str, int] = {}
    for name, endpoints in parsed.items():
        if not isinstance(endpoints, dict):
            continue
        for endpoint, values in endpoints.items():
            endpoint = str(endpoint)
            if is_local_ip(endpoint):
                continue
            if not isinstance(values, dict):
                continue
            total_bytes = sum_packet_sizes(values.get("packet_sizes", {}))
            out[name] = out.get(name, 0) + total_bytes
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize bytes sent to remote endpoints (LAN vs WAN).")
    ap.add_argument("--parsed-dir", required=True, help="Directory containing parsed JSON files.")
    ap.add_argument("--month", default="jan2024", help="Month token in filenames (default: jan2024).")
    ap.add_argument("--mode", choices=["no_frida", "frida"], default="no_frida", help="Mode token (default: no_frida).")
    ap.add_argument("--out", default="bytes_to_remote_endpoints.json", help="Output JSON (default: bytes_to_remote_endpoints.json).")
    args = ap.parse_args()

    d = Path(args.parsed_dir)
    month = args.month
    mode = args.mode

    lan_apps = load_json(d / f"same_pcapdroid_{mode}_{month}.json")
    lan_dev = load_json(d / f"same_moniotr_{mode}_{month}.json")
    wan_apps = load_json(d / f"different_pcapdroid_{mode}_{month}.json")
    wan_dev = load_json(d / f"different_moniotr_{mode}_{month}.json")

    out = {
        "LAN": {
            "apps": accumulate_remote_bytes(lan_apps),
            "devices": accumulate_remote_bytes(lan_dev),
        },
        "WAN": {
            "apps": accumulate_remote_bytes(wan_apps),
            "devices": accumulate_remote_bytes(wan_dev),
        },
    }

    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
