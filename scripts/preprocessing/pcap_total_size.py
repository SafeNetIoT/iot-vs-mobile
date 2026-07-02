#!/usr/bin/env python3
"""
Sum the total byte size of .pcap files in a dataset.

Supports two layouts:
1) Flat directory: <folder>/*.pcap
2) "monitor" layout: <folder>/<device>/<experiment>/*.pcap
   (enabled with --monitor)
"""

from __future__ import annotations

import argparse
from pathlib import Path


def iter_pcaps_flat(folder: Path):
    yield from folder.glob("*.pcap")


def iter_pcaps_monitor(folder: Path):
    # folder/<device>/<experiment>/*.pcap
    for device_dir in sorted(p for p in folder.iterdir() if p.is_dir()):
        print(f"Analyzing device: {device_dir.name}")
        for exp_dir in sorted(p for p in device_dir.iterdir() if p.is_dir()):
            print(f"  Analyzing experiment: {exp_dir.name}")
            yield from sorted(exp_dir.glob("*.pcap"))


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for u in units:
        if size < 1024.0 or u == units[-1]:
            return f"{size:.2f} {u}"
        size /= 1024.0
    return f"{n} B"


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute total size of PCAP files in a folder.")
    parser.add_argument("folder", help="Folder containing PCAPs (flat) or device/experiment subfolders (monitor).")
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Use monitor layout: folder/<device>/<experiment>/*.pcap (default: flat folder/*.pcap).",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Print a human-readable size (KB/MB/GB).",
    )
    args = parser.parse_args()

    folder = Path(args.folder)
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder not found or not a directory: {folder}")

    total_size = 0
    pcap_count = 0

    pcaps = iter_pcaps_monitor(folder) if args.monitor else iter_pcaps_flat(folder)
    for pcap in pcaps:
        try:
            total_size += pcap.stat().st_size
            pcap_count += 1
        except OSError as e:
            print(f"Warning: could not stat {pcap}: {e}")

    size_str = human_bytes(total_size) if args.human else str(total_size)
    print(f"PCAP files: {pcap_count}")
    print(f"Total size: {size_str}")


if __name__ == "__main__":
    main()
