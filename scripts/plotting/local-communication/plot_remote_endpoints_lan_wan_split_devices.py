#!/usr/bin/env python3
"""
plot_remote_endpoints_lan_wan_split_devices.py

Plot how remote-endpoint bytes split between LAN vs WAN for each device.

Logic (unchanged):
  - Input: bytes_to_remote_endpoints.json with:
      data["LAN"]["devices"], data["WAN"]["devices"]
  - For each device:
      LAN% = LAN / (LAN+WAN)
      WAN% = WAN / (LAN+WAN)
  - Sort by LAN%
  - Plot stacked bars and a 50% dotted reference line.

Example:
  python3 plot_remote_endpoints_lan_wan_split_devices.py \
    --json bytes_to_remote_endpoints.json \
    --out endpoints_devices_lan_wan_ratio.pdf
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def pretty(label: str) -> str:
    name = label
    name = name.replace("echodot5", "EchoDot v5")
    name = name.replace("echodot4", "EchoDot v4")
    name = name.replace("Honeywell_T6_Thermostat", "Honeywell")
    name = name.replace("furbo_dog_camera", "Furbo Dog")
    name = name.replace("lepro_light", "Lepro")
    name = name.replace("netatmo_weather_station", "Netatmo")
    name = name.replace("aqara_hubM2", "Aqara")
    name = name.replace("iROBOT_roomba", "iRobot")
    name = name.replace("tapo_plug110_38", "Tapo Plug")
    name = name.replace("govee_strip_light", "Govee")
    name = name.replace("Google_Nest_Wifi_Router", "Nest Wifi")
    name = name.replace("wiz_smart_bulb", "Wiz")
    name = name.replace("yeelight_bulb", "Yeelight")
    name = name.replace("reolink_doorbell", "Reolink")
    name = name.replace("geree_doorbell", "Geree")
    name = name.replace("ring_chime_pro", "Ring Chime")
    name = name.replace("ring_spotlight_camera", "Ring Spotlight")
    name = name.replace("arlo_camera_pro4", "Arlo")
    name = name.replace("wyze_cam_pan_v2", "Wyze")
    name = name.replace("boifun_baby", "Boifun Baby")
    name = name.replace("vtech_baby_camera", "VTech Baby")
    name = name.replace("google_nest_doorbell", "Nest Doorbell")
    name = name.replace("nest_cam", "Nest Cam")
    name = name.replace("alexa_swan_kettle", "Alexa Kettle")
    name = name.replace("meross_garage_door", "Meross Garage")
    name = name.replace("OKP_smart_vacuum", "OKP")
    name = name.replace("ecovacs_vacuum", "Ecovacs")
    name = name.replace("eufy_robovac", "Eufy")
    name = name.replace("withings_body_pressure_monitor", "Withings BPM")
    name = name.replace("Withings_Body_Pressure_Monitor", "Withings BPM")
    name = name.replace("sensibo_sky_sensor", "Sensibo")
    name = name.replace("blink_mini_camera", "Blink Mini")
    name = name.replace("switchbot_hub_mini_2", "Switchbot (2)")
    name = name.replace("switchbot_hub_mini_1", "Switchbot (1)")
    name = name.replace("petsafe_feeder", "Petsafe")

    return " ".join(w.capitalize() if not any(c.isupper() for c in w) else w for w in name.split())


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot LAN vs WAN split of remote-endpoint bytes per device.")
    ap.add_argument("--json", default="bytes_to_remote_endpoints.json", help="Input JSON path.")
    ap.add_argument("--out", default="endpoints_devices_lan_wan_ratio.pdf", help="Output PDF path.")
    args = ap.parse_args()

    data = json.loads(Path(args.json).read_text(encoding="utf-8"))

    lan_devices = data["LAN"]["devices"]
    wan_devices = data["WAN"]["devices"]

    all_devices = sorted(set(lan_devices.keys()) | set(wan_devices.keys()))

    lan_pct, wan_pct, labels = [], [], []
    for dev in all_devices:
        lan = lan_devices.get(dev, 0)
        wan = wan_devices.get(dev, 0)
        total = lan + wan
        if total == 0:
            lp, wp = 0.0, 0.0
        else:
            lp = 100.0 * lan / total
            wp = 100.0 * wan / total
        lan_pct.append(lp)
        wan_pct.append(wp)
        labels.append(pretty(dev))

    idx = np.argsort(lan_pct)
    lan_pct_sorted = [lan_pct[i] for i in idx]
    wan_pct_sorted = [wan_pct[i] for i in idx]
    labels_sorted = [labels[i] for i in idx]

    plt.rcParams.update({"font.size": 16})
    fig = plt.figure(figsize=(15, 3))
    x = np.arange(len(labels_sorted))

    plt.bar(x, lan_pct_sorted, label="LAN → devices (%)", color="black", edgecolor="black", width=0.5)
    plt.bar(
        x,
        wan_pct_sorted,
        bottom=lan_pct_sorted,
        label="WAN → devices (%)",
        color="white",
        edgecolor="black",
        width=0.5,
    )

    plt.axhline(50, linestyle="dotted", color="red", linewidth=3)
    plt.xticks(x, labels_sorted, rotation=35, ha="right")
    plt.tight_layout(pad=0.5)
    plt.savefig(args.out, bbox_inches="tight")
    plt.close(fig)

    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
