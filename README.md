# Device vs. App Analysis

> **Bridging Devices and Apps: A Joint Analysis of IoT Privacy and Communication**
> Carlotta Tagliaro, Martina Komsic, Gianluca Anselmi, Anna Maria Mandalari, and Martina Lindorfer
> *Publication details and DOI will be added after publication.*

## Overview

This repository contains the analysis pipeline used to study the network behavior and privacy implications of consumer IoT devices and their Android companion apps.

The study compares app-side and device-side communication under matched user interactions and two network settings:

- **WAN:** the phone and IoT device are connected to different networks, emulating remote control;
- **LAN:** the phone and IoT device are connected to the same local network.

The analysis focuses on:

1. differences between app-generated and device-generated traffic;
2. changes in communication when local connectivity is available;
3. contacted endpoints, countries, cloud providers, ports, and protocols;
4. tracking and analytics communication;
5. local communication;
6. personal and device-associated identifiers visible in analyzable app traffic;
7. consistency between observed traffic, privacy policies, and vendor data-access responses.

## Repository Structure

```text
Device-vs-App-Analysis/
├── README.md
├── LICENSE
├── CITATION.cff
├── SECURITY.md
├── DATA_AVAILABILITY.md
├── requirements.txt
├── .gitignore
├── config/
│   ├── device_name_map.json
│   └── .env.example
├── scripts/
│   ├── collection/
│   ├── preprocessing/
│   ├── enrichment/
│   │   ├── dns/
│   │   ├── endpoints/
│   │   └── providers/
│   ├── analysis/
│   │   ├── categories/
│   │   ├── country/
│   │   ├── endpoints/
│   │   ├── local_communication/
│   │   ├── privacy/
│   │   ├── protocols/
│   │   ├── providers/
│   │   └── tracking/
│   └── plotting/
│       ├── local_communication/
│       └── tracking/
├── data/
│   ├── reference/
│   ├── processed/
│   └── results/
├── figures/
├── docs/
└── legacy/
```

### Folder Summary

- `scripts/collection/` contains experiment orchestration and packet-capture extraction helpers.
- `scripts/preprocessing/` contains filtering, normalization, renaming, and format-conversion utilities.
- `scripts/enrichment/` contains DNS, hostname, endpoint, country, and provider enrichment steps.
- `scripts/analysis/` contains the analyses used to generate the paper results.
- `scripts/plotting/` contains scripts that generate the figures.
- `data/reference/` contains third-party lookup datasets, such as cloud-provider IP ranges and port mappings.
- `data/processed/` contains sanitized intermediate data required by later analysis steps.
- `data/results/` contains aggregate outputs reported in the paper.
- `figures/` contains generated plots.
- `docs/` contains reproducibility notes, data schemas, and third-party data documentation.
- `legacy/` contains unsupported historical scripts and may be removed in future versions.

## Data Availability and Privacy

The repository intentionally excludes sensitive raw data, including:

- raw PCAP and PCAPNG captures;
- TLS key logs and decrypted captures;
- complete HTTP URLs and request or response payloads.

Only sanitized intermediate data, aggregate results, and selected figures are included. Some endpoint labels are pseudonymized while preserving their consistency across files. For complete access to the data, please contact us.

## Requirements

The scripts support Python 3 and use external tools including Wireshark/TShark, `editcap`, Frida, mitmproxy, and the MonIoTr testbed.

Create an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Some scripts require system-level dependencies, including:

- Wireshark/TShark;
- `editcap`;
- Android Debug Bridge;
- Frida;
- mitmproxy.

## Configuration

Optional scripts use external services such as IPinfo, Shodan, and DNSDB. Credentials must be supplied through environment variables and must not be committed to the repository.

Copy the example configuration:

```bash
cp config/.env.example .env
```

Example variables:

```bash
IPINFO_TOKEN=
SHODAN_API_KEY=
DNSDB_API_KEY=

MONIOTR_WIFI_SSID=
MONIOTR_WIFI_PASS=
MONIOTR_PHONE_MAC=
MONIOTR_TAG_SCRIPT=
MONIOTR_TRAFFIC_DIR=
```

Load the configuration before running scripts:

```bash
set -a
source .env
set +a
```

## Analysis Workflow

At a high level, it consists of the following stages.

### 1. Collect or prepare traffic data

Collection helpers are available in:

```text
scripts/collection/
```

These scripts process PCAPs, DNS records, TLS key logs, and mitmproxy captures. Raw capture data is not included in the repository.

### 2. Preprocess traffic

Preprocessing scripts normalize device names, summarize capture sizes, and convert raw tool output into structured formats:

```text
scripts/preprocessing/
```

### 3. Enrich endpoints

Endpoint enrichment includes:

- DNS and reverse-DNS resolution;
- TLS certificate hostname extraction;
- provider identification;
- country mapping;
- endpoint categorization.

```text
scripts/enrichment/
```

### 4. Run analyses

The main analyses are grouped by topic:

```text
scripts/analysis/categories/
scripts/analysis/country/
scripts/analysis/endpoints/
scripts/analysis/local_communication/
scripts/analysis/privacy/
scripts/analysis/protocols/
scripts/analysis/providers/
scripts/analysis/tracking/
```

Most scripts expose their arguments through:

```bash
python path/to/script.py --help
```

### 5. Generate figures

Plotting scripts are stored separately from the analysis code:

```text
scripts/plotting/
```

Generated figures are written to:

```text
figures/
```

## Reproducibility Scope

This repository is a research artifact rather than a general-purpose traffic-analysis framework.

Some collection steps depend on:

- the MonIoTr testbed;
- Android devices configured for Frida and mitmproxy;
- the original experiment directory structure;
- access to third-party enrichment services.

To make the artifact useful without the original infrastructure, the repository includes sanitized aggregate results and the scripts needed to reproduce the analyses and figures from those results.

## Citation

Please cite the associated paper when using this repository.

```bibtex
@inproceedings{tagliaro-device-app-analysis,
  author    = {Carlotta Tagliaro and Martina Komsic and Gianluca Anselmi and Anna Maria Mandalari and Martina Lindorfer},
  title     = {Bridging Devices and Apps: A Joint Analysis of IoT Privacy and Communication},
  booktitle = {To appear},
  year      = {2026}
}
```

## License

The code and released data may require different licenses.

See `LICENSE` before reusing or redistributing material from this repository.

## Contact

For questions about the artifact, please contact carlotta@seclab.wien.