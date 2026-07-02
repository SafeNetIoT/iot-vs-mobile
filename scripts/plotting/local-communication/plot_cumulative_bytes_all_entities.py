#!/usr/bin/env python3
"""
plot_cumulative_bytes_all_entities.py

Plot cumulative-bytes-over-time curves (LAN vs WAN) for every entity in the input JSONs.

This is useful for producing one figure per device/app.
It supports two "labels" for output organization:
  - moniotr   (device-side)
  - pcapdroid (app-side)

Input JSON format (both LAN and WAN):
  { "<entity>": { "<second>": <bytes>, ... }, ... }

Example (devices, MonIoTr):
  python plot_cumulative_bytes_all_entities.py \
    --lan same_local_communication_moniotr_no_frida_jan2024.json \
    --wan different_local_communication_moniotr_no_frida_jan2024.json \
    --label moniotr \
    --outdir figures/cdfs \
    --xmax 300 --vline 100 --logy

Example (apps, PCAPdroid):
  python plot_cumulative_bytes_all_entities.py \
    --lan same_local_communication_pcapdroid_no_frida_jan2024.json \
    --wan different_local_communication_pcapdroid_no_frida_jan2024.json \
    --label pcapdroid \
    --outdir figures/cdfs \
    --xmax 300 --vline 100
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Tuple, List

import numpy as np
import matplotlib.pyplot as plt


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def cumulative(series: Dict[str, Any]) -> Tuple[List[int], np.ndarray]:
    # Accept both int and str second keys
    secs = sorted(int(s) for s in series.keys())
    vals = [int(series.get(str(s), series.get(s, 0))) for s in secs]
    return secs, np.cumsum(vals)


def plot_entity(entity: str, lan_series: Dict[str, Any], wan_series: Dict[str, Any],
                out_path: Path, xmax: int, vline: int | None, logy: bool) -> None:
    sx, cy_lan = cumulative(lan_series)
    dx, cy_wan = cumulative(wan_series)

    plt.figure(figsize=(10, 6))
    plt.plot(sx, cy_lan, linestyle="--", label="LAN")
    plt.plot(dx, cy_wan, linestyle="-", label="WAN")

    if vline is not None:
        plt.axvline(x=vline, color="red", linestyle="--", linewidth=2)

    plt.xlim(0, xmax)
    if logy:
        plt.yscale("log")

    plt.xlabel("Time (seconds)")
    plt.ylabel("Cumulative bytes")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot cumulative bytes over time (LAN vs WAN) for all entities.")
    ap.add_argument("--lan", required=True, help="LAN JSON file (entity -> {sec:bytes}).")
    ap.add_argument("--wan", required=True, help="WAN JSON file (entity -> {sec:bytes}).")
    ap.add_argument("--label", choices=["moniotr", "pcapdroid"], required=True, help="Used to name output folder.")
    ap.add_argument("--outdir", default=".", help="Base output directory.")
    ap.add_argument("--xmax", type=int, default=300, help="Max x-axis seconds (default: 300).")
    ap.add_argument("--vline", type=int, default=100, help="Vertical marker time in seconds (default: 100).")
    ap.add_argument("--no-vline", action="store_true", help="Disable vertical marker.")
    ap.add_argument("--logy", action="store_true", help="Use log scale for y-axis.")
    ap.add_argument("--include", nargs="*", default=None, help="Optional: only plot these entities.")
    ap.add_argument("--exclude", nargs="*", default=[], help="Optional: exclude these entities.")
    args = ap.parse_args()

    lan = load_json(Path(args.lan))
    wan = load_json(Path(args.wan))

    out_base = Path(args.outdir) / args.label
    vline = None if args.no_vline else args.vline

    exclude = set(args.exclude)
    include = set(args.include) if args.include else None

    # Only plot entities present in both
    entities = sorted(set(lan.keys()) & set(wan.keys()))
    if include is not None:
        entities = [e for e in entities if e in include]
    entities = [e for e in entities if e not in exclude]

    written = 0
    skipped = 0

    for entity in entities:
        lan_series = lan.get(entity)
        wan_series = wan.get(entity)
        if not isinstance(lan_series, dict) or not isinstance(wan_series, dict):
            skipped += 1
            continue
        out_path = out_base / f"{entity}.pdf"
        plot_entity(entity, lan_series, wan_series, out_path, args.xmax, vline, args.logy)
        written += 1

    print(f"Wrote {written} PDF(s) to {out_base} (skipped {skipped}).")


if __name__ == "__main__":
    main()
