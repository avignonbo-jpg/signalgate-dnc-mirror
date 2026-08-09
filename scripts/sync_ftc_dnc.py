#!/usr/bin/env python3
"""
sync_ftc_dnc.py — fetches the FTC Do Not Call complaint dataset via the real
api.data.gov-backed FTC REST API, validates it, and writes a single flat JSON
file for SignalGate Pulse to fetch over plain HTTPS.

This exists so the FTC_API_KEY never ships inside the Android app. The key
lives only as a GitHub Actions secret in THIS repo. The Android app fetches
the published output file from raw.githubusercontent.com — a public GET,
no credential involved at all.

Mirrors the exact pagination/field constants from the app's original
ReliableSourceManager.kt so behavior stays equivalent:
  - FTC_PAGE_SIZE = 1000, FTC_MAX_PAGES = 50 (same as the app previously used)
  - field read from each row: "phone_number"
  - length bounds: 10-15 digits (MIN/MAX_NUMBER_LENGTH)

Quarantine behavior: if the fetch comes back empty, too small relative to the
last published snapshot, or malformed, this script exits non-zero WITHOUT
touching the output file. The workflow's commit step only runs on success —
so a bad upstream response never overwrites the last-known-good file that's
actually live for users.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

FTC_API_BASE = "https://api.ftc.gov/v0/dnc-complaints"
FTC_PAGE_SIZE = 1000
FTC_MAX_PAGES = 50
MIN_NUMBER_LENGTH = 10
MAX_NUMBER_LENGTH = 15
OUTPUT_PATH = "dnc-numbers.json"

# If the newly fetched count drops below this fraction of the previous
# published count, treat it as a likely-poisoned/broken upstream response
# and refuse to publish, rather than silently shrinking users' blocklist.
MIN_ACCEPTABLE_RATIO = 0.5


def sanitize_number(raw: str) -> str:
    """Digits and a single leading + only — mirrors SanitizationEngine's intent."""
    raw = raw.strip()
    cleaned = re.sub(r"[^0-9+]", "", raw)
    return cleaned


def fetch_page(api_key: str, page: int) -> dict:
    url = f"{FTC_API_BASE}?api_key={api_key}&per_page={FTC_PAGE_SIZE}&page={page}"
    req = urllib.request.Request(url, headers={"User-Agent": "signalgate-dnc-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} fetching page {page}")
        return json.loads(response.read().decode("utf-8"))


def fetch_all_numbers(api_key: str) -> list[str]:
    numbers: list[str] = []
    for page in range(1, FTC_MAX_PAGES + 1):
        try:
            body = fetch_page(api_key, page)
        except (urllib.error.URLError, RuntimeError) as e:
            print(f"WARN: page {page} failed ({e}) — stopping pagination here", file=sys.stderr)
            break

        data = body.get("data")
        if not data:
            print(f"Page {page}: empty — end of dataset", file=sys.stderr)
            break

        for row in data:
            raw = str(row.get("phone_number", "")).strip()
            cleaned = sanitize_number(raw)
            if MIN_NUMBER_LENGTH <= len(cleaned) <= MAX_NUMBER_LENGTH:
                numbers.append(cleaned)

        print(f"Page {page}: {len(data)} records (running total: {len(numbers)})", file=sys.stderr)

    return sorted(set(numbers))


def load_previous_count() -> int:
    if not os.path.exists(OUTPUT_PATH):
        return 0
    try:
        with open(OUTPUT_PATH, "r") as f:
            return int(json.load(f).get("count", 0))
    except (json.JSONDecodeError, ValueError):
        return 0


def main() -> int:
    api_key = os.environ.get("FTC_API_KEY")
    if not api_key:
        print("ERROR: FTC_API_KEY environment variable not set", file=sys.stderr)
        return 1

    numbers = fetch_all_numbers(api_key)
    previous_count = load_previous_count()

    if not numbers:
        print("ERROR: fetch returned zero numbers — refusing to publish an empty file", file=sys.stderr)
        return 1

    if previous_count > 0 and len(numbers) < previous_count * MIN_ACCEPTABLE_RATIO:
        print(
            f"ERROR: fetched {len(numbers)} numbers, down from {previous_count} "
            f"(below {MIN_ACCEPTABLE_RATIO:.0%} threshold) — likely a broken upstream "
            f"response. Refusing to publish; last-known-good file stays live.",
            file=sys.stderr,
        )
        return 1

    output = {
        "source": "FTC Do Not Call Registry — api.ftc.gov/v0/dnc-complaints",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(numbers),
        "phone_numbers": numbers,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"OK: published {len(numbers)} numbers to {OUTPUT_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
