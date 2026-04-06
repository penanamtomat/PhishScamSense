"""
Data loading and preprocessing utilities.
Ingests data from threat intelligence feeds and local datasets.
"""

import csv
import logging
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


def load_csv_dataset(filepath: str | Path) -> tuple[list[str], list[int]]:
    """Load URLs and labels from a CSV file."""
    urls, labels = [], []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def fetch_openphish_feed() -> list[str]:
    """Fetch latest phishing URLs from OpenPhish community feed."""
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=30)
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()]
        logger.info(f"Fetched {len(urls)} URLs from OpenPhish")
        return urls
    except requests.RequestException as e:
        logger.error(f"Failed to fetch OpenPhish feed: {e}")
        return []


def fetch_phishtank_feed(api_key: str | None = None) -> list[str]:
    """Fetch latest phishing URLs from PhishTank."""
    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        if api_key:
            url = f"http://data.phishtank.com/data/{api_key}/online-valid.json"

        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        urls = [entry["url"] for entry in data]
        logger.info(f"Fetched {len(urls)} URLs from PhishTank")
        return urls
    except requests.RequestException as e:
        logger.error(f"Failed to fetch PhishTank feed: {e}")
        return []


def prepare_training_data(
    csv_path: str | Path | None = None,
    include_openphish: bool = True,
    include_phishtank: bool = False,
    phishtank_api_key: str | None = None,
) -> tuple[list[str], list[int]]:
    """Combine local dataset with threat intelligence feeds."""
    urls, labels = [], []

    if csv_path:
        csv_urls, csv_labels = load_csv_dataset(csv_path)
        urls.extend(csv_urls)
        labels.extend(csv_labels)

    if include_openphish:
        phish_urls = fetch_openphish_feed()
        urls.extend(phish_urls)
        labels.extend([1] * len(phish_urls))

    if include_phishtank:
        pt_urls = fetch_phishtank_feed(phishtank_api_key)
        urls.extend(pt_urls)
        labels.extend([1] * len(pt_urls))

    logger.info(f"Total dataset: {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} benign)")
    return urls, labels
