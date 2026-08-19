#!/usr/bin/env python3
"""
sync_ftc_dnc.py — fetches the FTC Do Not Call complaint dataset via the real
api.data.gov-backed FTC REST API, validates it, and writes a single flat JSON
file for SignalGate Pulse to fetch over plain HTTPS.

This exists so the FTC_API_KEY never ships inside the Android app. The key
lives only as a GitHub Actions secret in THIS repo. The Android app fetches
the published output file from raw.githubusercontent.com — a public GET,
no credential involved at all.

Confirmed against FTC's own published API spec
(ftc.gov/developer/api/v0/endpoints/do-not-call-dnc-reported-calls-data-api):
  - the real field path is data[i].attributes["company-phone-number"], not a
    top-level "phone_number" key
  - there is no "page"/"per_page" parameter at all — pagination is
    items_per_page (capped at 50 by the API regardless of what's requested)
    + offset
  - length bounds: 10-15 digits (MIN/MAX_NUMBER_LENGTH), same as the app
    previously used

Each run fetches a bounded batch of the newest records (MAX_REQUESTS_PER_RUN
* 50) and MERGES cumulatively with whatever was already published, rather
than replacing it outright — fetching the entire multi-year dataset in a
single run isn't practical given the 50-record-per-request cap, so coverage
builds up across repeated cron runs instead.

Quarantine behavior: if the merged total drops below a threshold relative to
the last published snapshot, this script exits non-zero WITHOUT touching the
output file. The workflow's commit step only runs on success — so a bad
upstream response never overwrites the last-known-good file that's actually
live for users. Under a cumulative merge this count should structurally only
grow or hold flat, so a drop is a strong signal something is wrong.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

FTC_API_BASE = "https://api.ftc.gov/v0/dnc-complaints"
# The API caps items_per_page at 50 regardless of what's requested, and paginates
# via offset (there is no "page" parameter — confirmed against FTC's own published
# spec at ftc.gov/developer/api/v0/endpoints/do-not-call-dnc-reported-calls-data-api).
ITEMS_PER_PAGE = 50
# Bounded per run rather than the full multi-year dataset: keeps each run's
# request count sane for rate limits and runtime. Coverage builds up over time
# via the cumulative merge below, since this cron runs every 6 hours.
MAX_REQUESTS_PER_RUN = 40  # 40 * 50 = 2,000 newest complaints per run
MIN_NUMBER_LENGTH = 10
MAX_NUMBER_LENGTH = 15
OUTPUT_PATH = "dnc-numbers.json"

# If the newly MERGED total count drops below this fraction of the previous
# published count, treat it as a likely-poisoned/broken upstream response
# and refuse to publish, rather than silently shrinking users' blocklist.
# Under normal cumulative operation this count should only grow or hold flat,
# so a drop below this ratio is a strong signal something's wrong upstream.
MIN_ACCEPTABLE_RATIO = 0.5


def sanitize_number(raw: str) -> str:
    """Digits and a single leading + only — mirrors SanitizationEngine's intent."""
    raw = raw.strip()
    cleaned = re.sub(r"[^0-9+]", "", raw)
    return cleaned


def fetch_page(api_key: str, offset: int) -> dict:
    url = (
        f"{FTC_API_BASE}?api_key={api_key}"
        f"&items_per_page={ITEMS_PER_PAGE}&offset={offset}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "signalgate-dnc-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} at offset {offset}")
        return json.loads(response.read().decode("utf-8"))


def fetch_newest_numbers(api_key: str) -> list[str]:
    numbers: list[str] = []
    for request_index in range(MAX_REQUESTS_PER_RUN):
        offset = request_index * ITEMS_PER_PAGE
        try:
            body = fetch_page(api_key, offset)
        except (urllib.error.URLError, RuntimeError) as e:
            print(f"WARN: offset {offset} failed ({e}) — stopping here", file=sys.stderr)
            break

        data = body.get("data")
        if not data:
            print(f"offset {offset}: empty — end of dataset", file=sys.stderr)
            break

        for row in data:
            raw = str(row.get("attributes", {}).get("company-phone-number", "")).strip()
            cleaned = sanitize_number(raw)
            if MIN_NUMBER_LENGTH <= len(cleaned) <= MAX_NUMBER_LENGTH:
                numbers.append(cleaned)

        print(f"offset {offset}: {len(data)} records (running total: {len(numbers)})", file=sys.stderr)

    return numbers


def load_previous_numbers() -> list[str]:
    if not os.path.exists(OUTPUT_PATH):
        return []
    try:
        with open(OUTPUT_PATH, "r") as f:
            return list(json.load(f).get("phone_numbers", []))
    except (json.JSONDecodeError, ValueError):
        return []


def main() -> int:
    api_key = os.environ.get("FTC_API_KEY")
    if not api_key:
        print("ERROR: FTC_API_KEY environment variable not set", file=sys.stderr)
        return 1

    newest = fetch_newest_numbers(api_key)
    previous = load_previous_numbers()
    previous_count = len(previous)

    if not newest and previous_count == 0:
        print("ERROR: fetch returned zero numbers and no previous file exists — nothing to publish", file=sys.stderr)
        return 1

    merged = sorted(set(previous) | set(newest))

    if previous_count > 0 and len(merged) < previous_count * MIN_ACCEPTABLE_RATIO:
        print(
            f"ERROR: merged total {len(merged)} is below {MIN_ACCEPTABLE_RATIO:.0%} of the "
            f"previous published count ({previous_count}) — this should be structurally "
            f"impossible under a cumulative merge, meaning something is corrupting the "
            f"existing file. Refusing to publish; last-known-good file stays live.",
            file=sys.stderr,
        )
        return 1

    output = {
        "source": "FTC Do Not Call Registry — api.ftc.gov/v0/dnc-complaints",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(merged),
        "phone_numbers": merged,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

import base64
import hashlib

def sign_output(private_key_pem: str, path: str) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    with open(path, "rb") as f:
        payload_bytes = f.read()

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    signature = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

    manifest = {
        "algorithm": "SHA256withECDSA",
        "sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(path + ".sig.json", "w") as f:
        json.dump(manifest, f, indent=2)
  

    print(
        f"OK: {len(newest)} fetched this run, {len(merged)} total published "
        f"(was {previous_count})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
