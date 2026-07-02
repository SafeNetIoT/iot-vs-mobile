#!/usr/bin/env bash
set -euo pipefail

# decrypt_pcaps_with_sslkeys.sh
#
# Decrypt PCAPs using Wireshark/TShark SSL key log files via editcap.
#
# Assumptions:
#   - For each <capture>.pcap, there is a key log file <capture>.txt
#   - The key file may live in a parallel directory (default: replace /PCAPdroid with /ssl_keys)
#
# Example:
#   ./decrypt_pcaps_with_sslkeys.sh \
#     --pcap-dir /path/to/experiment/usa_experiments/frida/feb2024/PCAPdroid \
#     --keys-dir /path/to/experiment/usa_experiments/frida/feb2024/ssl_keys \
#     --out-dir  /path/to/experiment/usa_experiments/frida/feb2024/PCAPdroid_decrypted
#
# Notes:
#   - Requires: editcap (Wireshark)
#   - Produces: <name>_decrypted.pcap (or .pcapng if input is .pcapng)

usage() {
  echo "Usage: $0 --pcap-dir DIR [--keys-dir DIR] [--out-dir DIR]"
  exit 1
}

PCAP_DIR=""
KEYS_DIR=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap-dir) PCAP_DIR="$2"; shift 2 ;;
    --keys-dir) KEYS_DIR="$2"; shift 2 ;;
    --out-dir)  OUT_DIR="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -z "$PCAP_DIR" ]] && usage
[[ -d "$PCAP_DIR" ]] || { echo "PCAP dir not found: $PCAP_DIR" >&2; exit 1; }

# Default keys/out dirs if not provided
if [[ -z "$KEYS_DIR" ]]; then
  KEYS_DIR="${PCAP_DIR/\/PCAPdroid/\/ssl_keys}"
fi
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="${PCAP_DIR/\/PCAPdroid/\/PCAPdroid_decrypted}"
fi

mkdir -p "$OUT_DIR"

shopt -s nullglob
for file in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
  [[ -f "$file" ]] || continue

  base="$(basename "$file")"
  stem="${base%.*}"
  ext="${base##*.}"

  key_file="$KEYS_DIR/${stem}.txt"
  out_file="$OUT_DIR/${stem}_decrypted.${ext}"

  if [[ ! -f "$key_file" ]]; then
    echo "[skip] missing key file: $key_file"
    continue
  fi

  echo "Decrypting: $base -> $(basename "$out_file")"
  editcap --inject-secrets tls,"$key_file" "$file" "$out_file"
done

echo "Done. Output in: $OUT_DIR"
