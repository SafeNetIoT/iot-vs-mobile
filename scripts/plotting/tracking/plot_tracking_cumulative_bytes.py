#!/usr/bin/env python3
"""
plot_tracking_cumulative_bytes.py

Plot cumulative bytes sent to Tracking & Analytics endpoints over time, per device.

Input JSON format (expected):
{
  "<device>": {
    "<tracking_domain>": {
      "<second>": <bytes_in_that_second>,
      ...
    },
    ...
  },
  ...
}

Each curve is the cumulative sum of bytes over time for a given tracking domain.
(Despite the legacy name "CDF", this is a cumulative-bytes time series.)

Example:
  python plot_tracking_cumulative_bytes.py \
    --input traffic_same_moniotr_no_frida_jan2024.json \
    --device Honeywell_T6_Thermostat \
    --outdir moniotr_same_plots \
    --xmax 300 \
    --vline 100
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


def thousands_k(x: float, _pos: int) -> str:
    # 12000 -> "12k"
    return f"{x * 1e-3:.0f}k"


def seconds_suffix(x: float, _pos: int) -> str:
    return f"{int(x)}s"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict at top-level in {path}, got {type(data).__name__}")
    return data


def plot_device(
    device: str,
    device_data: Dict[str, Any],
    out_path: Path,
    xmax: int,
    vline: int | None,
    font_size: int,
) -> None:
    if not device_data:
        return

    plt.rcParams.update({"font.size": font_size})
    fig, ax = plt.subplots(figsize=(10, 6))

    # device_data: tracking_domain -> {sec -> bytes}
    for tracking_domain, values in device_data.items():
        if not isinstance(values, dict) or not values:
            continue

        # sort seconds numerically
        seconds = sorted(int(s) for s in values.keys() if str(s).isdigit())
        if not seconds:
            continue

        bytes_per_sec = [int(values.get(str(s), 0)) for s in seconds]
        cumulative = np.cumsum(bytes_per_sec)

        ax.plot(seconds, cumulative, label=str(tracking_domain), linestyle="-")

    ax.xaxis.set_major_formatter(FuncFormatter(seconds_suffix))
    ax.yaxis.set_major_formatter(FuncFormatter(thousands_k))
    ax.set_xlabel("")
    ax.set_ylabel("Cumulative bytes")
    ax.set_xlim(0, xmax)

    if vline is not None:
        ax.axvline(x=vline, color="red", linestyle="--", linewidth=2)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True)
    ax.legend(loc="right", bbox_to_anchor=(1, 0.7))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot cumulative tracking bytes over time per device.")
    ap.add_argument("--input", required=True, help="Path to traffic_<exp>_<layout>_...json")
    ap.add_argument(
        "--device",
        default=None,
        help="Device name to plot (default: plot all devices in the JSON).",
    )
    ap.add_argument("--outdir", default=".", help="Output directory for PDFs.")
    ap.add_argument("--xmax", type=int, default=300, help="Max x-axis seconds (default: 300).")
    ap.add_argument("--vline", type=int, default=100, help="Vertical marker in seconds (default: 100).")
    ap.add_argument("--no-vline", action="store_true", help="Disable vertical marker line.")
    ap.add_argument("--font-size", type=int, default=14, help="Base font size (default: 14).")
    args = ap.parse_args()

    in_path = Path(args.input)
    data = load_json(in_path)

    outdir = Path(args.outdir)
    vline = None if args.no_vline else args.vline

    if args.device:
        if args.device not in data:
            raise SystemExit(f"Device '{args.device}' not found in {in_path.name}")
        plot_device(
            args.device,
            data[args.device],
            outdir / f"{args.device}.pdf",
            args.xmax,
            vline,
            args.font_size,
        )
        print(f"Wrote: {outdir / f'{args.device}.pdf'}")
    else:
        written = 0
        for device, device_data in data.items():
            if not isinstance(device_data, dict) or not device_data:
                continue
            plot_device(
                device,
                device_data,
                outdir / f"{device}.pdf",
                args.xmax,
                vline,
                args.font_size,
            )
            written += 1
        print(f"Wrote {written} PDF(s) to {outdir}")


if __name__ == "__main__":
    main()
