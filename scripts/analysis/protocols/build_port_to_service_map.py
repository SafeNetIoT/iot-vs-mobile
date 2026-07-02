#!/usr/bin/env python3
"""
build_port_to_service_map.py

Build a JSON mapping from port (or port-range) to service name from a text file.

Input format: one mapping per line, either:
  443 https
  https 443
  8000-8100 custom-service

Empty lines and comments (#...) are ignored.

Example:
  python build_port_to_service_map.py \
    --input port_services.txt \
    --output ports_map.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Optional


PORT_RE = re.compile(r"^\d+(-\d+)?$")


def parse_line(line: str) -> Optional[tuple[str, Optional[str]]]:
    # strip comments and whitespace
    line = line.split("#", 1)[0].strip()
    if not line:
        return None

    parts = [p for p in line.split() if p]
    if len(parts) < 1:
        return None

    # Common cases: "<port> <service>" or "<service> <port>"
    if len(parts) >= 2:
        a, b = parts[0], parts[1]
        if PORT_RE.match(a):
            port, service = a, b
        elif PORT_RE.match(b):
            port, service = b, a
        else:
            return None
        return port, service

    # One-token line like "443" -> unknown service
    if PORT_RE.match(parts[0]):
        return parts[0], None

    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Build port->service mapping from a text file.")
    ap.add_argument("--input", default="port_services.txt", help="Input text file (default: port_services.txt).")
    ap.add_argument("--output", default="ports_map.json", help="Output JSON file (default: ports_map.json).")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path}")

    mapping: Dict[str, Optional[str]] = {}

    for raw in in_path.read_text(encoding="utf-8").splitlines():
        parsed = parse_line(raw)
        if not parsed:
            continue
        port, service = parsed
        mapping[port] = service

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    print(f"Wrote: {out_path} ({len(mapping)} entries)")


if __name__ == "__main__":
    main()
