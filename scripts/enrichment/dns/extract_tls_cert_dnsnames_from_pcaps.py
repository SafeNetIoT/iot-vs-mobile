#!/usr/bin/env python3
"""
extract_tls_cert_dnsnames_from_pcaps.py

Extract TLS certificate DNS names from PCAPs and build/update an IP -> cert-name map.

What it does:
  - Scans all .pcap/.pcapng files in a folder
  - Filters for TLS ServerHello handshake packets (default tshark filter)
  - Reads the x509 DNS name (tls.x509ce.dNSName / x509ce_dnsname in pyshark)
  - Maps the *remote* peer IP to the DNS name:
      if pkt.ip.src is private RFC1918, it uses pkt.ip.dst; otherwise pkt.ip.src

Inputs:
  - Folder containing PCAP files
  - Optional existing JSON mapping to update (default: common_name_ip_map.json)

Output:
  - JSON dict: { "<ip>": "<dnsname>", ... }

Example:
  python extract_tls_cert_dnsnames_from_pcaps.py \
    --pcap-dir /path/to/pcaps \
    --out common_name_ip_map.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

import pyshark

# Optional: helps when running inside notebooks
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


def is_private_ipv4(ip: str) -> bool:
    return ip.startswith(RFC1918_PREFIXES)


def load_map(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict in {path}, got {type(data).__name__}")
    return {str(k): str(v) for k, v in data.items()}


def save_map(path: Path, mapping: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)


def get_tls_dnsname(pkt: Any) -> Optional[str]:
    """
    Try to extract the certificate DNS name as exposed by pyshark.
    Field naming varies across tshark versions.
    """
    try:
        tls = pkt["TLS"]
    except Exception:
        return None

    # Common pyshark attribute name used in your script
    if hasattr(tls, "x509ce_dnsname"):
        val = getattr(tls, "x509ce_dnsname")
        return str(val) if val else None

    # Sometimes tshark exposes it under a slightly different key
    for attr in ("x509ce_dNSName", "x509ce_dnsName", "x509ce_dnsname"):
        if hasattr(tls, attr):
            val = getattr(tls, attr)
            return str(val) if val else None

    return None


def iter_pcaps(folder: Path):
    for ext in ("*.pcap", "*.pcapng"):
        yield from sorted(folder.glob(ext))


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract TLS cert DNS names from PCAPs and build IP->DNSName map.")
    ap.add_argument("--pcap-dir", required=True, help="Folder containing .pcap/.pcapng files.")
    ap.add_argument("--out", default="common_name_ip_map.json", help="Output JSON map path.")
    ap.add_argument(
        "--in-map",
        default="common_name_ip_map.json",
        help="Existing JSON map to update (default: same as --out).",
    )
    ap.add_argument(
        "--display-filter",
        default="tls.handshake.type == 2 || ssl.handshake.type == 2",
        help="TShark display filter (default matches ServerHello for TLS/SSL dissectors).",
    )
    args = ap.parse_args()

    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        raise SystemExit(f"PCAP directory not found: {pcap_dir}")

    in_map_path = Path(args.in_map)
    out_path = Path(args.out)

    mapping = load_map(in_map_path)

    pcaps = list(iter_pcaps(pcap_dir))
    if not pcaps:
        raise SystemExit(f"No .pcap/.pcapng files found in: {pcap_dir}")

    updated = 0
    scanned = 0

    for pcap in pcaps:
        print(f"Scanning {pcap.name}")
        scanned += 1

        cap = pyshark.FileCapture(
            str(pcap),
            display_filter=args.display_filter,
            keep_packets=False,
        )
        try:
            for pkt in cap:
                if "IP" not in pkt or "TLS" not in pkt:
                    continue

                src = str(pkt.ip.src)
                dst = str(pkt.ip.dst)

                peer_ip = dst if is_private_ipv4(src) else src
                dns = get_tls_dnsname(pkt)
                if not dns:
                    continue

                # Update only if new or changed
                if mapping.get(peer_ip) != dns:
                    mapping[peer_ip] = dns
                    updated += 1
        finally:
            cap.close()

    save_map(out_path, mapping)
    print(f"Done. PCAPs scanned: {scanned}. Entries updated/added: {updated}.")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
