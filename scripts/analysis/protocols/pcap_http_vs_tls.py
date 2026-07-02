#!/usr/bin/env python3
import sys
from collections import defaultdict

import pyshark

HTTP_LAYERS = {"http", "http2"}
TLS_LAYERS = {"tls", "ssl"}  # "ssl" appears in older dissectors/captures

def classify_packet(pkt) -> str:
    # Some packets may throw if layers are weird; be defensive.
    try:
        layers = {ly.layer_name for ly in pkt.layers}
    except Exception:
        return "other"

    # Prefer "application view": if HTTP is visible, count as HTTP even if TLS exists too
    if layers & HTTP_LAYERS:
        return "http"
    if layers & TLS_LAYERS:
        return "tls"
    return "other"

def get_frame_len(pkt) -> int:
    # frame.len is the on-the-wire frame length, good for byte accounting
    try:
        return int(pkt.length)  # pyshark exposes frame.len as pkt.length
    except Exception:
        try:
            return int(pkt.frame_info.len)
        except Exception:
            return 0

def main(pcap_path: str):
    totals = defaultdict(lambda: {"packets": 0, "bytes": 0})

    cap = pyshark.FileCapture(
        pcap_path,
        keep_packets=False,      # don't store packets in RAM
        use_json=True            # faster/more reliable parsing
    )

    for pkt in cap:
        cat = classify_packet(pkt)
        totals[cat]["packets"] += 1
        totals[cat]["bytes"] += get_frame_len(pkt)

    cap.close()

    total_bytes = sum(v["bytes"] for v in totals.values()) or 1
    total_pkts = sum(v["packets"] for v in totals.values()) or 1

    for cat in ["http", "tls", "other"]:
        b = totals[cat]["bytes"]
        p = totals[cat]["packets"]
        print(
            f"{cat.upper():5s}  packets={p:8d} ({p/total_pkts:6.2%})   "
            f"bytes={b:12d} ({b/total_bytes:6.2%})"
        )

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_http_vs_tls.py <file.pcap>")
        sys.exit(1)
    main(sys.argv[1])
