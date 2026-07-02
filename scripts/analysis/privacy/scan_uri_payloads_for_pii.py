#!/usr/bin/env python3
"""
scan_uri_payloads_for_pii.py

Scan extracted URI+payload logs for PII-like patterns (regex + keyword hits).

Input format:
  JSON list: [{"uri": "...", "payload": ...}, ...]

By default:
  - runs your original regex list EXACTLY as written in the old script
  - runs your original keyword list (case-insensitive by default)

Example:
  python scan_uri_payloads_for_pii.py --input uris_and_payloads.json

Write a JSON report:
  python scan_uri_payloads_for_pii.py --input uris_and_payloads.json --out pii_hits.json

Keep original keyword behavior (case-sensitive substring match):
  python scan_uri_payloads_for_pii.py --input uris_and_payloads.json --case-sensitive-keywords

Add a more permissive IPv4 finder (keeps your original IPv4 regex too):
  python scan_uri_payloads_for_pii.py --input uris_and_payloads.json --extra-loose-ipv4
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# ORIGINAL PATTERNS (UNCHANGED)
# ----------------------------
# Source: https://blog.netwrix.com/2018/05/29/regular-expressions-for-beginners-how-to-get-started-discovering-sensitive-data/

EMAIL_REGEX = r'[\w\.=-]+@[\w\.-]+\.[\w]{2,3}'
IPV4_REGEX = r'^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$'
DATES_MMDDYYYY_REGEX = r'([1][12]|[0]?[1-9])[\/-]([3][01]|[12]\d|[0]?[1-9])[\/-](\d{4}|\d{2})'
MASTERCARD_REGEX = r'(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}'
VISA_REGEX = r'\b([4]\d{3}[\s]\d{4}[\s]\d{4}[\s]\d{4}|[4]\d{3}[-]\d{4}[-]\d{4}[-]\d{4}|[4]\d{3}[.]\d{4}[.]\d{4}[.]\d{4}|[4]\d{3}\d{4}\d{4}\d{4})\b'
AMERICAN_EXPRESS_REGEX = r'3[47][0-9]{13}'

# Source: https://support.milyli.com/docs/resources/regex/general-pii-regex
# TODO: verify this works
UK_PHONE_REGEX = r'\b([0O]?[1lI][1lI])?[4A][4A][\dOIlZEASB]{10,11}\b'
IPV6_REGEX = r'\b([\d\w]{4}|0)(\:([\d\w]{4}|0)){7}\b'

# Source: https://www.cardinalpath.com/blog/what-you-need-to-know-about-google-analytics-personally-identifiable-information
SSN_REGEX = r'\d{3}-?\d{2}-?\d{4}'

# Source: https://stackoverflow.com/questions/4260467/what-is-a-regular-expression-for-a-mac-address
MAC_REGEX = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'

# Source: https://stackoverflow.com/questions/14051007/regex-for-multiple-imei-validation
IMEI_REGEX = r'[0-9]{15}(,[0-9]{15})*'

# KEYWORD LISTS
BIRTHDAY_LIST = ['dob', 'date of birth', 'birthdate', 'birth date', 'birthday', 'b-day', 'bday']
PASSPORT_LIST = ['passport', 'travel document']

# TODO: add weight, height, pulse
INCOMPLETE_LIST = [
    'name', 'email', 'address', 'race', 'gender', 'ssn', 'social security number',
    'visa', 'driver', 'licence', 'plate number', 'disability', 'location',
    'sexual orientation', 'medical', 'place of birth', 'payment', 'imei'
]

# TODO: add username, password, authorization keys

REGEX_LIST = [
    EMAIL_REGEX, IPV4_REGEX, IPV6_REGEX, MASTERCARD_REGEX, VISA_REGEX,
    AMERICAN_EXPRESS_REGEX, UK_PHONE_REGEX, MAC_REGEX, IMEI_REGEX
]


# ----------------------------
# ADD-ONS (OPTIONAL)
# ----------------------------
# Looser IPv4 finder (keeps your original anchored regex too)
EXTRA_IPV4_LOOSE_REGEX = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'


def _compile_patterns(extra_loose_ipv4: bool) -> List[Tuple[str, re.Pattern]]:
    patterns: List[Tuple[str, re.Pattern]] = [
        ("email", re.compile(EMAIL_REGEX)),
        ("ipv4_anchored", re.compile(IPV4_REGEX)),
        ("ipv6", re.compile(IPV6_REGEX)),
        ("mastercard", re.compile(MASTERCARD_REGEX)),
        ("visa", re.compile(VISA_REGEX)),
        ("amex", re.compile(AMERICAN_EXPRESS_REGEX)),
        ("uk_phone", re.compile(UK_PHONE_REGEX)),
        ("mac", re.compile(MAC_REGEX)),
        ("imei", re.compile(IMEI_REGEX)),
        # SSN exists in file but wasn't in REGEX_LIST originally; keep it available but off by default.
        # (You can turn it on by adding it explicitly below if you want.)
    ]
    if extra_loose_ipv4:
        patterns.append(("ipv4_loose", re.compile(EXTRA_IPV4_LOOSE_REGEX)))
    return patterns


def _keyword_hits(text: str, case_sensitive: bool) -> List[str]:
    hits = []
    hay = text if case_sensitive else text.lower()
    for kw in INCOMPLETE_LIST:
        needle = kw if case_sensitive else kw.lower()
        if needle in hay:
            hits.append(kw)
    return sorted(set(hits))


def _regex_hits(text: str, patterns: List[Tuple[str, re.Pattern]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for label, pat in patterns:
        found = pat.findall(text)
        if found:
            # flatten tuples (e.g., MAC regex groups)
            flat: List[str] = []
            for x in found:
                if isinstance(x, tuple):
                    flat.append("".join(x))
                else:
                    flat.append(str(x))
            out[label] = sorted(set(flat))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan uri/payload JSON for PII-like regex/keyword hits.")
    ap.add_argument("--input", required=True, help="Input JSON list with {uri,payload}.")
    ap.add_argument("--out", default=None, help="Optional JSON report output.")
    ap.add_argument("--quiet", action="store_true", help="Do not print hits, only write --out.")
    ap.add_argument("--case-sensitive-keywords", action="store_true", help="Use original case-sensitive keyword matching.")
    ap.add_argument("--extra-loose-ipv4", action="store_true", help="Also match IPv4 inside longer strings.")
    args = ap.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("Input must be a JSON list of objects.")

    patterns = _compile_patterns(extra_loose_ipv4=args.extra_loose_ipv4)

    report: List[Dict[str, Any]] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue

        entry: Dict[str, Any] = {"index": idx}
        any_hit = False

        for field in ("uri", "payload"):
            if field not in item:
                continue
            txt = str(item[field])

            rh = _regex_hits(txt, patterns)
            kh = _keyword_hits(txt, case_sensitive=args.case_sensitive_keywords)

            if rh or kh:
                any_hit = True
                entry[field] = {"regex_hits": rh, "keyword_hits": kh}

        if any_hit:
            report.append(entry)
            if not args.quiet:
                print(json.dumps(entry, indent=2))

    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        if not args.quiet:
            print(f"Wrote: {args.out} ({len(report)} entries)")

    if args.quiet and not args.out:
        print(f"Found hits in {len(report)} entries (use --out to save report).")


if __name__ == "__main__":
    main()
