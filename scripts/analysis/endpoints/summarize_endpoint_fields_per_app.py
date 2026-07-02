#!/usr/bin/env python3
"""
summarize_endpoint_fields_per_app.py

Summarize per-app distributions of endpoint fields (category/country/provider/ports)
from parsed traffic JSON files (nofrida + optional frida merge).

Example:
  python summarize_endpoint_fields_per_app.py \
    --nofrida nuc_traffic_no_frida_pcapdroid.json \
    --frida nuc_traffic_frida_pcapdroid.json \
    --out stats_per_app.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict


RFC1918_RE = re.compile(
    r"^(10(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|((172\.(1[6-9]|2\d|3[01]))|192\.168)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})$"
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def bump(m: Dict[str, int], k: str) -> None:
    m[k] = m.get(k, 0) + 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize endpoint fields per app from parsed traffic.")
    ap.add_argument("--nofrida", required=True, help="Parsed no-frida JSON file.")
    ap.add_argument("--frida", default=None, help="Optional parsed frida JSON file (merged).")
    ap.add_argument("--out", required=True, help="Output JSON path.")
    args = ap.parse_args()

    nofrida: Dict[str, Any] = load_json(Path(args.nofrida))
    frida: Dict[str, Any] = load_json(Path(args.frida)) if args.frida else {}

    stats: Dict[str, Any] = {}

    for app, endpoints in nofrida.items():
        if not isinstance(endpoints, dict):
            continue

        seen = set()
        cats: Dict[str, int] = {}
        countries: Dict[str, int] = {}
        providers: Dict[str, int] = {}
        ports: Dict[str, int] = {}

        def process(endpoint: str, val: Any) -> None:
            if endpoint in seen or RFC1918_RE.match(endpoint):
                return
            seen.add(endpoint)
            if isinstance(val, dict):
                bump(cats, str(val.get("categorization") or "other"))
                bump(countries, str(val.get("country") or "other"))
                bump(providers, str(val.get("provider") or "other"))
                for p in (val.get("ports") or []):
                    bump(ports, str(p))

        for e, val in endpoints.items():
            process(str(e), val)

        if app in frida and isinstance(frida[app], dict):
            for e, val in frida[app].items():
                process(str(e), val)

        stats[app] = {
            "unique_endpoints": len(seen),
            "countries": dict(sorted(countries.items(), key=lambda kv: kv[1], reverse=True)),
            "categories": dict(sorted(cats.items(), key=lambda kv: kv[1], reverse=True)),
            "providers": dict(sorted(providers.items(), key=lambda kv: kv[1], reverse=True)),
            "ports": dict(sorted(ports.items(), key=lambda kv: kv[1], reverse=True)),
        }

    Path(args.out).write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
