#!/usr/bin/env python3
"""
extract_http_uris_and_payloads_from_pcaps.py

Extract HTTP/HTTP2 URIs and (when available) payloads from PCAPs.

Inputs:
  - moniotr layout: <root>/moniotr/<device>/<functionality>/*.pcap
Output:
  - JSON files containing [{"uri": "...", "payload": ...}, ...]

Security warning:
  Output may contain credentials, session tokens, account identifiers, device identifiers, complete query strings, and personal information. Store output outside the repository and review it before sharing.

Example:
  python extract_http_uris_and_payloads_from_pcaps.py \
    --pcap-root /path/to/experiment/different_network_experiments/no_frida/jan2024/moniotr \
    --outdir /path/to/experiment/different_network_experiments/no_frida/jan2024/uris_and_payloads_moniotr
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pyshark

try:
    import nest_asyncio  # type: ignore
    nest_asyncio.apply()
except Exception:
    pass


def http2_uri_payload(http2_layer: Any) -> Tuple[Optional[str], Optional[Any]]:
    try:
        method = getattr(http2_layer, "headers_method", None)
        scheme = getattr(http2_layer, "headers_scheme", None)
        authority = getattr(http2_layer, "headers_authority", None)
        path = getattr(http2_layer, "headers_path", None)
        if not (scheme and authority and path):
            return None, None
        uri = f"{scheme}://{authority}{path}"
        payload = getattr(http2_layer, "json_member_with_value", None) if method == "POST" else None
        return uri, payload
    except Exception:
        return None, None


def extract_pairs(pcap: Path) -> List[Dict[str, Any]]:
    pairs: List[Dict[str, Any]] = []
    cap = pyshark.FileCapture(str(pcap), display_filter="http or http2", keep_packets=False)
    try:
        for pkt in cap:
            item: Dict[str, Any] = {}

            if "HTTP" in pkt:
                http = pkt.http
                uri = getattr(http, "request_full_uri", None) or getattr(http, "response_for_uri", None)
                if not uri:
                    continue
                item["uri"] = str(uri)
                payload = getattr(http, "file_data", None)
                if payload is not None:
                    item["payload"] = str(payload)
                pairs.append(item)
                continue

            if "HTTP2" in pkt:
                # sometimes last layer is http2; sometimes pkt.http2 exists
                layer = pkt.layers[-1] if pkt.layers and pkt.layers[-1].layer_name == "http2" else getattr(pkt, "http2", None)
                if not layer:
                    continue
                uri, payload = http2_uri_payload(layer)
                if not uri:
                    continue
                item["uri"] = uri
                if payload is not None:
                    item["payload"] = payload
                pairs.append(item)
    finally:
        cap.close()

    return pairs


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract HTTP URIs and payloads from moniotr PCAPs.")
    ap.add_argument("--pcap-root", required=True, help="Root moniotr folder containing device subfolders.")
    ap.add_argument("--outdir", required=True, help="Output directory for JSON files.")
    args = ap.parse_args()

    root = Path(args.pcap_root)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    written = 0
    for device_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for func_dir in sorted(p for p in device_dir.iterdir() if p.is_dir()):
            for pcap in sorted(func_dir.glob("*.pcap")):
                pairs = extract_pairs(pcap)
                if not pairs:
                    continue
                out_path = outdir / f"{device_dir.name}_{func_dir.name}_{pcap.stem}.json"
                out_path.write_text(json.dumps(pairs, indent=2, sort_keys=True), encoding="utf-8")
                written += 1
                print(f"Wrote {out_path} ({len(pairs)} entries)")

    print(f"Done. Wrote {written} JSON file(s).")


if __name__ == "__main__":
    main()
