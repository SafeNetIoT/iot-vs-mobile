#!/usr/bin/env python3
"""
extract_ip_to_host_from_http_pcaps.py

Extract an IP -> hostname map from decrypted HTTP/HTTP2 traffic in PCAP files.

Logic:
  - Iterates *.pcap/*.pcapng in an input folder
  - Uses pyshark display filter: "http or http2"
  - For each packet, picks the peer IP:
      if src is private RFC1918 -> use dst, else use src
  - Extracts hostnames from:
      HTTP  : request_full_uri / response_for_uri
      HTTP2 : headers_authority (":authority")

Output:
  - JSON dict: { "<ip>": "<hostname>", ... }

Example:
  python extract_ip_to_host_from_http_pcaps.py \
    --pcap-dir ./decrypted_pcaps \
    --out dns_map.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

import pyshark

# Optional: helps when running in environments with an existing event loop
try:
    import nest_asyncio  # type: ignore
    nest_asyncio.apply()
except Exception:
    pass


RFC1918_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_local_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918_PREFIXES)


def host_from_uri(uri: str) -> Optional[str]:
    """
    Robustly extract host from a full URI or host-like string.
    """
    uri = uri.strip()
    if not uri:
        return None

    parsed = urlparse(uri)
    if parsed.netloc:
        return parsed.netloc

    # handle URIs missing scheme
    parsed2 = urlparse("https://" + uri)
    if parsed2.netloc:
        return parsed2.netloc

    # fallback: split by path
    return uri.replace("http://", "").replace("https://", "").split("/")[0] or None


def extract_from_pcap(pcap_path: Path, dns_map: Dict[str, str], display_filter: str) -> None:
    cap = pyshark.FileCapture(str(pcap_path), display_filter=display_filter, keep_packets=False)
    try:
        for pkt in cap:
            if "IP" not in pkt:
                continue

            src = str(pkt.ip.src)
            dst = str(pkt.ip.dst)
            peer_ip = dst if is_local_ip(src) else src

            # HTTP
            if "HTTP" in pkt:
                http = pkt.http
                uri = None
                if hasattr(http, "request_full_uri"):
                    uri = str(http.request_full_uri)
                elif hasattr(http, "response_for_uri"):
                    uri = str(http.response_for_uri)

                if uri:
                    host = host_from_uri(uri)
                    if host:
                        dns_map[peer_ip] = host
                continue

            # HTTP/2
            if "HTTP2" in pkt:
                try:
                    for layer in pkt.layers:
                        if layer.layer_name == "http2" and hasattr(layer, "headers_authority"):
                            host = str(layer.headers_authority).strip()
                            if host:
                                dns_map[peer_ip] = host
                except Exception:
                    pass
    finally:
        cap.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract IP->host mapping from decrypted HTTP/HTTP2 PCAPs.")
    ap.add_argument("--pcap-dir", required=True, help="Directory containing PCAP files.")
    ap.add_argument("--out", required=True, help="Output JSON file.")
    ap.add_argument("--filter", default="http or http2", help='TShark display filter (default: "http or http2").')
    args = ap.parse_args()

    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        raise SystemExit(f"PCAP directory not found: {pcap_dir}")

    dns_map: Dict[str, str] = {}

    pcaps = sorted(list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng")))
    if not pcaps:
        raise SystemExit(f"No .pcap/.pcapng files found in: {pcap_dir}")

    for pcap in pcaps:
        print(f"Analyzing {pcap.name}")
        extract_from_pcap(pcap, dns_map, args.filter)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dns_map, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Wrote {len(dns_map)} IP->host entries to {out_path}")


if __name__ == "__main__":
    main()
