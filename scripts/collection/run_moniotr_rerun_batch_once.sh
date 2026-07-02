#!/usr/bin/env bash
set -euo pipefail

# run_moniotr_rerun_batch_once.sh
#
# Rerun MonIoTr experiments for multiple devices based on per-device config files.
# Each config file is expected to be a single line with semicolon-separated fields:
#   phone_id;name;name_exp;package;mac_address;tap1;tap2;...;tap9
#
# Example:
#   export MONIOTR_WIFI_SSID="<lab-ssid>"
#   export MONIOTR_WIFI_PASS="<lab-password>"
#   export MONIOTR_PHONE_MAC="<phone-mac>"
#   export MONIOTR_TAG_SCRIPT="/path/to/tag-experiment.sh"
#
#   ./run_moniotr_rerun_batch_once.sh \
#     --traffic-dir ./captures \
#     --iterations 2 \
#     --sleep-between-taps 10 \
#     --post-action-wait 300 \
#     amazon_kettle arlo blink_mini_camera
#
# Notes:
#   - Requires adb on PATH
#   - Requires /opt/moniotr/bin/tag-experiment.sh on this machine

DEVICE_FILES=("$@")
[[ -n "$SSID" ]] || {
  echo "Set MONIOTR_WIFI_SSID or pass --ssid." >&2
  exit 1
}

[[ -n "$WIFI_PASS" ]] || {
  echo "Set MONIOTR_WIFI_PASS." >&2
  exit 1
}

[[ -n "$PHONE_PCAP_MAC" ]] || {
  echo "Set MONIOTR_PHONE_MAC." >&2
  exit 1
}

[[ -x "$TAG_EXPERIMENT" ]] || {
  echo "MonIoTr tag script is not executable: $TAG_EXPERIMENT" >&2
  exit 1
}

TRAFFIC_DIR="${MONIOTR_TRAFFIC_DIR:-./captures}"
SSID="${MONIOTR_WIFI_SSID:-}"
WIFI_PASS="${MONIOTR_WIFI_PASS:-}"
PHONE_PCAP_MAC="${MONIOTR_PHONE_MAC:-}"
TAG_EXPERIMENT="${MONIOTR_TAG_SCRIPT:-/opt/moniotr/bin/tag-experiment.sh}"

ITERATIONS=2
SLEEP_BETWEEN_TAPS=10
POST_ACTION_WAIT=300
SLEEP_BETWEEN_DEVICES=60
PHONE_PCAP_TAG="phone_pcap"

# FILENAMES=("amazon_kettle" "arlo" "baifun" "blink_mini_camera" "bose_speaker" "chromecast" "echodot4" "echodot5" "ecovacs" "eufy_cleaner" "front_ring_camera" "furbo" "geree_cam" "google_nest_doorbell" "google_nest_hub" "govee" "honeywell" "lepro" "meross" "nest_cam" "netatmo" "okp" "petsafe" "reolink_doorbell" "ring_chime_pro" "ring_doorbell" "roomba" "sensibo" "sonos_speaker" "switchbot_dd" "switchbot_hub_mini_1" "tapo_smartplug" "vtech" "withing_pressure" "wiz" "wyze_cam" "yeelight" "nest_wifi")

usage() {
  echo "Usage: $0 [options] <device_config_files...>"
  echo "Options:"
  echo "  --traffic-dir DIR"
  echo "  --ssid SSID"
  echo "  --iterations N"
  echo "  --sleep-between-taps SECONDS"
  echo "  --post-action-wait SECONDS"
  echo "  --sleep-between-devices SECONDS"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --traffic-dir) TRAFFIC_DIR="$2"; shift 2 ;;
    --ssid) SSID="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --sleep-between-taps) SLEEP_BETWEEN_TAPS="$2"; shift 2 ;;
    --post-action-wait) POST_ACTION_WAIT="$2"; shift 2 ;;
    --sleep-between-devices) SLEEP_BETWEEN_DEVICES="$2"; shift 2 ;;
    -h|--help) usage ;;
    --*) echo "Unknown option: $1" >&2; usage ;;
    *) break ;;
  esac
done

[[ $# -lt 1 ]] && usage
DEVICE_FILES=("$@")

mkdir -p "$TRAFFIC_DIR"

echo "[setup] Cancelling previous phone capture tag (if any)"
"$TAG_EXPERIMENT" cancel "$PHONE_PCAP_MAC" "$PHONE_PCAP_TAG" || true
sleep 2

echo "[setup] Starting phone capture tag"
"$TAG_EXPERIMENT" start "$PHONE_PCAP_MAC" "$PHONE_PCAP_TAG"
sleep 2

ensure_wifi() {
  local phone_id="$1"
  local expected="$2"
  local pass="$3"

  local status
  status="$(adb -s "$phone_id" shell dumpsys netstats | grep -E 'iface=wlan.*networkId' || true)"

  until [[ "$status" == *"$expected"* ]]; do
    echo "[wifi] not on $expected; reconnecting..."
    sleep 10
    adb -s "$phone_id" shell "su -c 'cmd wifi connect-network ${expected} wpa2 ${pass}'" || true
    status="$(adb -s "$phone_id" shell dumpsys netstats | grep -E 'iface=wlan.*networkId' || true)"
  done
  echo "[wifi] connected to $expected"
}

for cfg in "${DEVICE_FILES[@]}"; do
  echo "============================================================"
  echo "[device] $cfg"
  [[ -f "$cfg" ]] || { echo "[error] config file not found: $cfg" >&2; continue; }

  # Read the single config line (semicolon-separated)
  IFS=";" read -r PHONE_ID NAME NAME_EXP PACKAGE MAC_ADDRESS TAP1 TAP2 TAP3 TAP4 TAP5 TAP6 TAP7 TAP8 TAP9 < "$cfg"
  TAPS=("$TAP1" "$TAP2" "$TAP3" "$TAP4" "$TAP5" "$TAP6" "$TAP7" "$TAP8" "$TAP9")

  for ((i=1; i<=ITERATIONS; i++)); do
    echo "[iter] ${NAME} iteration ${i}/${ITERATIONS}"

    ensure_wifi "$PHONE_ID" "$SSID" "$WIFI_PASS"

    # Launch app
    adb -s "$PHONE_ID" shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
    sleep 2

    # Cancel/start MonIoTr experiment for this device
    "$TAG_EXPERIMENT" cancel "$MAC_ADDRESS" "$NAME_EXP" || true
    sleep 2
    "$TAG_EXPERIMENT" start "$MAC_ADDRESS" "$NAME_EXP"
    sleep 2

    # Ring orientation workaround
    if [[ "$NAME" == "ring_doorbell" ]]; then
      echo "[workaround] disabling auto-rotate for Ring"
      adb -s "$PHONE_ID" shell settings put system accelerometer_rotation 0 || true
    fi

    # Replay taps/swipes
    for tap in "${TAPS[@]}"; do
      if [[ -z "${tap}" ]]; then
        echo "[tap] empty"
      else
        echo "[tap] input ${tap}"
        adb -s "$PHONE_ID" shell input ${tap}
        sleep "$SLEEP_BETWEEN_TAPS"
      fi
    done

    echo "[wait] ${POST_ACTION_WAIT}s capture window"
    sleep "$POST_ACTION_WAIT"

    echo "[stop] stopping MonIoTr experiment for ${NAME_EXP}"
    "$TAG_EXPERIMENT" stop "$MAC_ADDRESS" "$NAME_EXP" "$TRAFFIC_DIR"
    sleep 5

    adb -s "$PHONE_ID" shell am force-stop "$PACKAGE" || true
  done

  echo "[cooldown] sleeping ${SLEEP_BETWEEN_DEVICES}s before next device"
  sleep "$SLEEP_BETWEEN_DEVICES"
done

echo "[final] stopping phone capture tag"
"$TAG_EXPERIMENT" stop "$PHONE_PCAP_MAC" "$PHONE_PCAP_TAG" "$TRAFFIC_DIR"
sleep 5

echo "Done."


