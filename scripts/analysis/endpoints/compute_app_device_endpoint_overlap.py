#!/usr/bin/env python3
"""
compute_app_device_endpoint_overlap.py

Compute overlap between app-side and device-side traffic per app/device.

Inputs:
  Parsed JSON files in the format:
    { "<app>": { "<endpoint>": {"IPs":[...], ...}, ... }, ... }

Computes:
  - common endpoints per app (endpoint keys present in both)
  - common IPs per app (intersection of IP lists for matching endpoints)
  - summary stats (mean/stdev of per-app overlap; total unique shared IPs)

Example:
  python compute_app_device_endpoint_overlap.py \
    --parsed-dir ./parsed-files \
    --experiment different \
    --month jan2024 \
    --out common_overlap_different.json

  # If you already have common_ips_per_app_<exp>.json and only want stats:
  python compute_app_device_endpoint_overlap.py --from-json common_ips_per_app_different.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return data


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def compute_overlap(moniotr: Dict[str, Any], pcapdroid: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    common_endpoints: Dict[str, Set[str]] = {}
    common_ips: Dict[str, Set[str]] = {}

    for app, endpoints in moniotr.items():
        if not isinstance(endpoints, dict):
            continue
        if app not in pcapdroid or not isinstance(pcapdroid[app], dict):
            continue

        common_endpoints.setdefault(app, set())
        common_ips.setdefault(app, set())

        other_endpoints = pcapdroid[app]

        for endpoint, values in endpoints.items():
            endpoint = str(endpoint)
            if endpoint in other_endpoints:
                common_endpoints[app].add(endpoint)

                ips1 = set((values or {}).get("IPs", []) or []) if isinstance(values, dict) else set()
                ips2 = set((other_endpoints[endpoint] or {}).get("IPs", []) or []) if isinstance(other_endpoints[endpoint], dict) else set()
                common_ips[app].update({str(ip) for ip in (ips1 & ips2)})

    return common_endpoints, common_ips


def summarize_common_ips(common_ips: Dict[str, List[str]]) -> Dict[str, Any]:
    per_app_counts = [len(v) for v in common_ips.values()]
    all_shared_ips: Set[str] = set()
    for v in common_ips.values():
        all_shared_ips.update(v)

    return {
        "apps": len(common_ips),
        "total_unique_shared_ips": len(all_shared_ips),
        "mean_shared_ips_per_app": statistics.mean(per_app_counts) if per_app_counts else 0.0,
        "stdev_shared_ips_per_app": statistics.stdev(per_app_counts) if len(per_app_counts) >= 2 else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute endpoint/IP overlap between app-side and device-side traffic.")
    ap.add_argument("--parsed-dir", default="./parsed-files", help="Folder containing parsed JSON files.")
    ap.add_argument("--experiment", default="different", help="Experiment token used in filenames (same/different).")
    ap.add_argument("--month", default="jan2024", help="Month token used in filenames (default: jan2024).")
    ap.add_argument("--out", default=None, help="Write overlap JSON to this path.")
    ap.add_argument("--from-json", default=None, help="If set, skip computation and only summarize this JSON (app->list of IPs).")
    args = ap.parse_args()

    if args.from_json:
        common = load_json(Path(args.from_json))
        stats = summarize_common_ips({k: list(v) for k, v in common.items()})
        print(json.dumps(stats, indent=2))
        return

    d = Path(args.parsed_dir)
    exp = args.experiment
    month = args.month

    frida_m = load_json(d / f"{exp}_moniotr_frida_{month}.json")
    nofrida_m = load_json(d / f"{exp}_moniotr_no_frida_{month}.json")
    frida_p = load_json(d / f"{exp}_pcapdroid_frida_{month}.json")
    nofrida_p = load_json(d / f"{exp}_pcapdroid_no_frida_{month}.json")

    # Reproduce your “combine across four pairings” logic:
    common_endpoints: Dict[str, Set[str]] = {}
    common_ips: Dict[str, Set[str]] = {}

    for mfile, pfile in [(frida_m, frida_p), (nofrida_m, nofrida_p), (frida_m, nofrida_p), (nofrida_m, frida_p)]:
        ce, ci = compute_overlap(mfile, pfile)
        for app, s in ce.items():
            common_endpoints.setdefault(app, set()).update(s)
        for app, s in ci.items():
            common_ips.setdefault(app, set()).update(s)

    # Serialize sets
    out_obj = {
        "common_endpoints_per_app": {a: sorted(list(s)) for a, s in common_endpoints.items()},
        "common_ips_per_app": {a: sorted(list(s)) for a, s in common_ips.items()},
        "summary": summarize_common_ips({a: sorted(list(s)) for a, s in common_ips.items()}),
    }

    if args.out:
        save_json(Path(args.out), out_obj)
        print(f"Wrote: {args.out}")
    else:
        print(json.dumps(out_obj["summary"], indent=2))


if __name__ == "__main__":
    main()
