#!/usr/bin/env python3
"""
report_lan_devices_local_vs_remote_ratio.py

Compute LAN -> devices: ratio between bytes to local endpoints and remote endpoints.

Logic (unchanged):
  - Reads:
      local["LAN"]["devices"]
      remote["LAN"]["devices"]
  - Prints total local bytes, total remote bytes, ratios and shares.
  - Optionally writes a per-device CSV with per-device local/remote shares.

Example:
  python report_lan_devices_local_vs_remote_ratio.py \
    --local bytes_to_local_endpoints.json \
    --remote bytes_to_remote_endpoints.json \
    --csv lan_devices_local_remote.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def human(n: float) -> str:
    return f"{n:,.0f}"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Compute LAN->devices local vs remote bytes ratio from two JSON files."
    )
    p.add_argument("--local", required=True, help="Path to bytes_to_local_endpoints.json")
    p.add_argument("--remote", required=True, help="Path to bytes_to_remote_endpoints.json")
    p.add_argument("--csv", help="Optional path to write per-device CSV")
    args = p.parse_args()

    local = load_json(Path(args.local))
    remote = load_json(Path(args.remote))

    try:
        lan_local = local["LAN"]["devices"]
        lan_remote = remote["LAN"]["devices"]
    except KeyError as e:
        raise SystemExit(
            f"Missing expected key in JSON: {e}. Expected structure: ['LAN']['devices']"
        )

    total_local = sum(lan_local.values())
    total_remote = sum(lan_remote.values())
    total = total_local + total_remote

    if total == 0:
        print("No bytes recorded (both local and remote are zero).")
        return

    ratio_local_over_remote = (total_local / total_remote) if total_remote else float("inf")
    ratio_remote_over_local = (total_remote / total_local) if total_local else float("inf")
    pct_local = 100.0 * total_local / total
    pct_remote = 100.0 * total_remote / total

    print("=== LAN -> devices: Local vs Remote Endpoints ===")
    print(f"Total local bytes : {human(total_local)}")
    print(f"Total remote bytes: {human(total_remote)}")
    if ratio_local_over_remote == float("inf"):
        print("Local/Remote ratio: inf (remote total is 0)")
    else:
        print(f"Local/Remote ratio: {ratio_local_over_remote:.6f}")
    if ratio_remote_over_local == float("inf"):
        print("Remote/Local ratio: inf (local total is 0)")
    else:
        print(f"Remote/Local ratio: {ratio_remote_over_local:.6f}")
    print(f"Shares           : local {pct_local:.2f}% | remote {pct_remote:.2f}%")

    all_devices = sorted(set(lan_local.keys()) | set(lan_remote.keys()))
    rows = []
    for dev in all_devices:
        loc = lan_local.get(dev, 0)
        rem = lan_remote.get(dev, 0)
        tot = loc + rem
        if tot == 0:
            loc_share = 0.0
            rem_share = 0.0
        else:
            loc_share = 100.0 * loc / tot
            rem_share = 100.0 * rem / tot
        rows.append(
            {
                "device": dev,
                "local_bytes": loc,
                "remote_bytes": rem,
                "local_share_%": round(loc_share, 4),
                "remote_share_%": round(rem_share, 4),
            }
        )

    print("\nPer-device (sorted by local_share_% desc):")
    rows_sorted = sorted(rows, key=lambda r: r["local_share_%"], reverse=True)
    header = ["device", "local_bytes", "remote_bytes", "local_share_%", "remote_share_%"]

    widths = {h: len(h) for h in header}
    for r in rows_sorted:
        for h in header:
            widths[h] = max(widths[h], len(str(r[h])))

    print(" | ".join(h.ljust(widths[h]) for h in header))
    print("-+-".join("-" * widths[h] for h in header))
    for r in rows_sorted:
        print(" | ".join(str(r[h]).ljust(widths[h]) for h in header))

    if args.csv:
        out = Path(args.csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            w.writerows(rows_sorted)
        print(f"\nWrote per-device CSV to: {out}")


if __name__ == "__main__":
    main()
