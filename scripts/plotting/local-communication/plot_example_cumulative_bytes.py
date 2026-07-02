#!/usr/bin/env python3
"""
plot_example_cumulative_bytes.py

Plot cumulative bytes over time for selected devices (LAN vs WAN).

Inputs:
  LAN JSON: {device: {sec: bytes, ...}, ...}
  WAN JSON: {device: {sec: bytes, ...}, ...}

Example:
  python plot_example_cumulative_bytes.py \
    --lan same_local_communication_moniotr_no_frida_jan2024.json \
    --wan different_local_communication_moniotr_no_frida_jan2024.json \
    --devices echodot5 iROBOT_roomba \
    --out examples_cdf.pdf
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import matplotlib.pyplot as plt


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def cumulative(series: Dict[str, Any]) -> tuple[list[int], np.ndarray]:
    secs = sorted(int(s) for s in series.keys())
    vals = [int(series[str(s)]) for s in secs]
    return secs, np.cumsum(vals)


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot cumulative bytes (LAN vs WAN) for selected devices.")
    ap.add_argument("--lan", required=True, help="LAN JSON file.")
    ap.add_argument("--wan", required=True, help="WAN JSON file.")
    ap.add_argument("--devices", nargs="+", required=True, help="Device keys to plot.")
    ap.add_argument("--xmax", type=int, default=300, help="Max x-axis seconds (default: 300).")
    ap.add_argument("--out", default=None, help="If set, save to PDF; otherwise show.")
    args = ap.parse_args()

    lan = load_json(Path(args.lan))
    wan = load_json(Path(args.wan))

    for dev in args.devices:
        if dev not in lan or dev not in wan:
            continue
        sx, cy_lan = cumulative(lan[dev])
        dx, cy_wan = cumulative(wan[dev])

        plt.plot(sx, cy_lan, linestyle="--", label=f"{dev} (LAN)")
        plt.plot(dx, cy_wan, linestyle="-", label=f"{dev} (WAN)")

    plt.yscale("log")
    plt.xlim(0, args.xmax)
    plt.xlabel("Time (seconds)")
    plt.ylabel("Cumulative bytes")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    if args.out:
        plt.savefig(args.out, bbox_inches="tight")
        plt.close()
        print(f"Wrote: {args.out}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
