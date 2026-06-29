"""Download the NSL-KDD dataset into ``data/``.

NSL-KDD is distributed by the Canadian Institute for Cybersecurity. This script
fetches the train/test splits from a public mirror. Override the URLs with the
NETSENTINEL_TRAIN_URL / NETSENTINEL_TEST_URL environment variables if needed.

Usage:
    python scripts/download_data.py
"""
from __future__ import annotations

import os
import sys
import urllib.request

# Add src/ to the path so this runs without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netsentinel import config  # noqa: E402

# Public NSL-KDD mirror (raw text files).
BASE = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master"
TRAIN_URL = os.getenv("NETSENTINEL_TRAIN_URL", f"{BASE}/KDDTrain%2B.txt")
TEST_URL = os.getenv("NETSENTINEL_TEST_URL", f"{BASE}/KDDTest%2B.txt")


def _download(url: str, dest) -> None:
    if dest.exists():
        print(f"  already present: {dest.name}")
        return
    print(f"  downloading {dest.name} ...")
    urllib.request.urlretrieve(url, dest)
    print(f"  saved {dest} ({dest.stat().st_size:,} bytes)")


def main() -> None:
    config.ensure_dirs()
    print(f"Downloading NSL-KDD into {config.DATA_DIR}")
    _download(TRAIN_URL, config.TRAIN_FILE)
    _download(TEST_URL, config.TEST_FILE)
    print("Done.")


if __name__ == "__main__":
    main()
