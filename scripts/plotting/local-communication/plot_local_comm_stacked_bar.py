#!/usr/bin/env python3
"""
plot_local_comm_stacked_bar.py

Plot stacked bars for local communication ratio:
  bottom = LAN ratio (%)
  top    = WAN ratio (%) stacked on LAN to show LAN+WAN visually

Inputs:
  --lan-local-bytes: JSON {device: bytes_to_local_in_LAN}
  --wan-local-bytes: JSON {device: bytes_to_local_in_WAN}
  --lan-total-bytes: JSON {device: total_bytes_in_LAN}
  --wan-total-bytes: JSON {device: total_bytes_in_WAN}

If you don't have total-bytes JSONs, you can pass remote-bytes instead and we compute totals.

Example:
  python plot_local_comm_stacked_bar.py \
    --lan-local-bytes same_local_communication_moniotr_no_frida_jan2024.json \
    --wan-local-bytes different_local_communication_moniotr_no_frida_jan2024.json \
    --lan-total-bytes same_total_traffic_moniotr_no_frida_jan2024.json \
    --wan-total-bytes different_total_traffic_moniotr_no_frida_jan2024.json \
    --out device_same_vs_different_local_comm_barplot.pdf
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import matplotlib.pyplot as plt


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def compute_ratio(local_bytes: Dict[str, Any], total_bytes: Dict[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for dev, lb in local_bytes.items():
        tb = total_bytes.get(dev, 0)
        try:
            lb_i = float(lb)
            tb_i = float(tb)
        except Exception:
            continue
        out[dev] = 0.0 if tb_i <= 0 else (lb_i * 100.0 / tb_i)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot stacked bar chart of local comm ratio (LAN vs WAN).")
    ap.add_argument("--lan-local-bytes", required=True, help="LAN local bytes JSON (device->bytes).")
    ap.add_argument("--wan-local-bytes", required=True, help="WAN local bytes JSON (device->bytes).")
    ap.add_argument("--lan-total-bytes", required=True, help="LAN total bytes JSON (device->bytes).")
    ap.add_argument("--wan-total-bytes", required=True, help="WAN total bytes JSON (device->bytes).")
    ap.add_argument("--name-map", default=None, help="Optional JSON mapping device_key -> pretty label.")
    ap.add_argument("--out", default="device_same_vs_different_local_comm_barplot.pdf", help="Output PDF.")
    ap.add_argument("--figsize-x", type=float, default=15.0, help="Figure width.")
    ap.add_argument("--figsize-y", type=float, default=3.0, help="Figure height.")
    args = ap.parse_args()

    lan_local = load_json(Path(args.lan_local_bytes))
    wan_local = load_json(Path(args.wan_local_bytes))
    lan_total = load_json(Path(args.lan_total_bytes))
    wan_total = load_json(Path(args.wan_total_bytes))
    name_map = load_json(Path(args.name_map)) if args.name_map else {}

    lan_ratio = compute_ratio(lan_local, lan_total)
    wan_ratio = compute_ratio(wan_local, wan_total)

    # common devices only
    devices = sorted(set(lan_ratio) & set(wan_ratio))
    devices.sort(key=lambda d: lan_ratio[d])  # sort by LAN ratio

    labels = [name_map.get(d, d) for d in devices]
    lan_vals = [lan_ratio[d] for d in devices]
    wan_vals = [wan_ratio[d] for d in devices]

    x = np.arange(len(devices))

    plt.figure(figsize=(args.figsize_x, args.figsize_y))
    plt.bar(x, lan_vals, width=0.5, label="Same Network (LAN)")
    plt.bar(x, wan_vals, width=0.5, bottom=lan_vals, label="Different Network (WAN)")
    plt.axhline(50, linestyle="dotted", linewidth=2)
    plt.ylabel("Local communication ratio (%)")
    plt.xticks(x, labels, rotation=35, ha="right", fontsize=10)
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.45)
    plt.savefig(args.out, bbox_inches="tight")
    plt.close()
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
