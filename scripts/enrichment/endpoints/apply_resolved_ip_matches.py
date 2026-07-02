#!/usr/bin/env python3
"""
apply_resolved_ip_matches.py

Fill an "unsolved IPs" mapping using a second file that contains resolved matches.

Inputs:
  --unsolved: JSON dict { "<ip>": "<hostname>" | null | <non-string>, ... }
  --resolved: JSON dict { "<ip>": {"match": "<hostname>"|null, ...}, ... }

Output:
  Updated unsolved JSON written to --out.

Example:
  python apply_resolved_ip_matches.py \
    --unsolved unsolved_ips_moniotr_updated.json \
    --resolved missing_ips_total_with_extra_data_updated_final.json \
    --out unsolved_ips_moniotr_updated.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Apply resolved IP matches to an unsolved IP mapping.")
    ap.add_argument("--unsolved", required=True, help="Unsolved IP JSON mapping.")
    ap.add_argument("--resolved", required=True, help="Resolved matches JSON (ip -> {match: ...}).")
    ap.add_argument("--out", required=True, help="Output JSON path for updated unsolved mapping.")
    args = ap.parse_args()

    unsolved: Dict[str, Any] = load_json(Path(args.unsolved))
    resolved: Dict[str, Any] = load_json(Path(args.resolved))

    total = 0
    candidates = 0
    filled = 0

    for ip, val in unsolved.items():
        total += 1
        if isinstance(val, str):
            continue
        candidates += 1
        if ip in resolved and isinstance(resolved[ip], dict):
            m = resolved[ip].get("match")
            if isinstance(m, str) and m:
                unsolved[ip] = m
                filled += 1

    save_json(Path(args.out), unsolved)
    print(f"Total IPs: {total} | unresolved candidates: {candidates} | filled: {filled}")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
