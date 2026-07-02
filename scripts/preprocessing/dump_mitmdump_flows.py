#!/usr/bin/env python3
"""
dump_mitmdump_flows.py

Read a mitmproxy dump file and print flow information.

Example:
  python dump_mitmdump_flows.py --input flows.dump --mode summary
  python dump_mitmdump_flows.py --input flows.dump --mode json --host graph.facebook.com
"""

from __future__ import annotations

import argparse
import json
from mitmproxy import http, io
from mitmproxy.exceptions import FlowReadException


def main() -> None:
    ap = argparse.ArgumentParser(description="Print flows from a mitmproxy dump.")
    ap.add_argument("--input", required=True, help="Path to mitmproxy dump file.")
    ap.add_argument("--mode", choices=["summary", "json"], default="summary", help="Output mode.")
    ap.add_argument("--host", default=None, help="Only include flows matching this request host.")
    args = ap.parse_args()

    with open(args.input, "rb") as logfile:
        freader = io.FlowReader(logfile)
        try:
            for f in freader.stream():
                if not isinstance(f, http.HTTPFlow):
                    continue
                if args.host and f.request.host != args.host:
                    continue

                if args.mode == "summary":
                    print(f"{f.request.method} {f.request.scheme}://{f.request.host}{f.request.path}")
                else:
                    print(json.dumps(f.get_state(), indent=2))
        except FlowReadException as e:
            raise SystemExit(f"Flow file corrupted: {e}")


if __name__ == "__main__":
    main()
