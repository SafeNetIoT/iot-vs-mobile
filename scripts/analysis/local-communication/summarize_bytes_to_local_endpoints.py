#!/usr/bin/env python3
"""
summarize_bytes_to_local_endpoints.py

Sum bytes to local endpoints for LAN -> devices.

Logic (unchanged):
  - reads: same_local_communication_moniotr_no_frida_jan2024.json
  - sums all per-second values per device
  - stores them in:
      bytes_to_local_endpoints["LAN"]["devices"][device]
  - writes: bytes_to_local_endpoints.json

Example:
  python summarize_bytes_to_local_endpoints.py \
    --input same_local_communication_moniotr_no_frida_jan2024.json \
    --out bytes_to_local_endpoints.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute bytes_to_local_endpoints JSON (LAN->devices only).")
    ap.add_argument(
        "--input",
        default="same_local_communication_moniotr_no_frida_jan2024.json",
        help="Input local-communication JSON (default matches original script).",
    )
    ap.add_argument(
        "--out",
        default="bytes_to_local_endpoints.json",
        help="Output JSON (default: bytes_to_local_endpoints.json).",
    )
    args = ap.parse_args()

    local_traffic = load_json(Path(args.input))

    bytes_to_local_endpoints = {
        "LAN": {"devices": {}, "apps": {}},
        "WAN": {"devices": {}, "apps": {}},
    }

    for device, seconds in local_traffic.items():
        for _second, traffic in seconds.items():
            if device not in bytes_to_local_endpoints["LAN"]["devices"]:
                bytes_to_local_endpoints["LAN"]["devices"][device] = 0
            bytes_to_local_endpoints["LAN"]["devices"][device] += traffic

    print(json.dumps(bytes_to_local_endpoints, indent=4))
    Path(args.out).write_text(json.dumps(bytes_to_local_endpoints, indent=4), encoding="utf-8")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
