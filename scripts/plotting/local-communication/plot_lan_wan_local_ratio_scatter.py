#!/usr/bin/env python3
"""
plot_lan_wan_local_ratio_scatter.py

Compute per-device ratio of cumulative local bytes (LAN/WAN) over time
and plot log10(average_ratio) as a scatter with device labels.

Inputs:
  SAME_FILE: JSON {device: {second: bytes, ...}, ...}
  DIFFERENT_FILE: JSON {device: {second: bytes, ...}, ...}

Example:
  python plot_lan_wan_local_ratio_scatter.py \
    --lan same_local_communication_moniotr_no_frida_jan2024.json \
    --wan different_local_communication_moniotr_no_frida_jan2024.json \
    --out heat_map_scatter.pdf \
    --exclude cosori_air_fryer coffee_maker_lavazza
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import matplotlib.pyplot as plt


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def cumulative_every_step(data: Dict[str, Any], step: int) -> Dict[int, int]:
    cum: Dict[int, int] = {}
    current_interval = 0
    current_sum = 0

    for sec_s, b in sorted(data.items(), key=lambda kv: int(kv[0])):
        sec = int(sec_s)
        while sec > current_interval:
            cum[current_interval] = current_sum
            current_interval += step
        current_sum += int(b)

    cum[current_interval] = current_sum
    return cum


def average_ratio(lan: Dict[int, int], wan: Dict[int, int], step: int) -> float:
    max_val = min(max(lan.keys()), max(wan.keys()))
    ratios: List[float] = []
    for t in range(0, max_val + 1, step):
        a = lan.get(t, 0)
        b = wan.get(t, 0)
        ratios.append(a / b if b != 0 else float(a))
    return sum(ratios) / len(ratios) if ratios else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description="Scatter of log10(avg LAN/WAN local bytes ratio) per device.")
    ap.add_argument("--lan", required=True, help="LAN local bytes JSON (device -> {sec:bytes}).")
    ap.add_argument("--wan", required=True, help="WAN local bytes JSON (device -> {sec:bytes}).")
    ap.add_argument("--step", type=int, default=10, help="Time step for cumulative sampling (default: 10s).")
    ap.add_argument("--exclude", nargs="*", default=[], help="Devices to exclude.")
    ap.add_argument("--out", default="heat_map_scatter.pdf", help="Output PDF.")
    args = ap.parse_args()

    lan_file = load_json(Path(args.lan))
    wan_file = load_json(Path(args.wan))
    exclude = set(args.exclude)

    values: Dict[str, float] = {}
    for dev, lan_series in lan_file.items():
        if dev in exclude or dev not in wan_file:
            continue
        wan_series = wan_file[dev]
        if not isinstance(lan_series, dict) or not isinstance(wan_series, dict):
            continue

        lan_c = cumulative_every_step(lan_series, args.step)
        wan_c = cumulative_every_step(wan_series, args.step)
        avg = average_ratio(lan_c, wan_c, args.step)
        if avg <= 0:
            avg = 0.001
        values[dev] = math.log10(avg)

    # Plot
    names = list(values.keys())
    y = list(values.values())
    x = np.arange(1, len(names) + 1)

    plt.figure(figsize=(12, 4))
    plt.scatter(x, y)
    plt.axhline(y=0, linestyle="-", linewidth=1)
    plt.xticks([])

    for i, name in enumerate(names):
        plt.text(x[i] + 0.1, y[i], name, ha="left", fontsize=9)

    plt.ylabel("log10(avg(LAN/WAN local bytes ratio))")
    plt.tight_layout()
    plt.savefig(args.out, bbox_inches="tight")
    plt.close()
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
