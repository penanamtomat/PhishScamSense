"""
Data loading and preprocessing utilities.
Ingests data from threat intelligence feeds and local datasets.
"""

import csv
import logging
import random
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Label mapping for CIC-Bell-DNS2021
CLASS_NAMES = ["benign", "phishing", "malware", "spam"]


def load_cic_bell_dns2021(
    data_dir: str | Path,
    max_benign: int | None = 100_000,
    seed: int = 42,
) -> tuple[list[str], list[int]]:
    """
    Load CIC-Bell-DNS2021 datasets from raw CSV files.

    Labels: 0=benign, 1=phishing, 2=malware, 3=spam

    The phishing CSV has multiple columns (PhishTank format); URL is at column index 1.
    All other files contain one URL per line (no header).

    Args:
        data_dir: Directory containing the four CSV files.
        max_benign: Cap on benign samples (random subsample). None = use all.
        seed: Random seed for reproducible subsampling.
    """
    data_dir = Path(data_dir)
    urls: list[str] = []
    labels: list[int] = []

    # benign (label=0) — one URL per line (may be bare domains without scheme)
    benign_path = data_dir / "benign_domains.csv"
    if benign_path.exists():
        benign_urls: list[str] = []
        with open(benign_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    if not url.startswith(("http://", "https://", "ftp://")):
                        url = "https://" + url  # real benign sites use HTTPS
                    benign_urls.append(url)
        # Add www. variants so the model sees both "example.com" and
        # "www.example.com" as benign (browsers often navigate to www.).
        www_variants = [
            u.replace("https://", "https://www.", 1)
            for u in benign_urls
            if not u.startswith("https://www.")
        ]
        # Add subdomain variants so the model sees common legitimate service
        # subdomains (mail., accounts., drive., etc.) as benign.
        # Without these, any URL with a subdomain looks suspicious because
        # the raw CIC benign set contains only bare domains.
        # Subdomain variants — use only neutral, non-suspicious subdomains.
        # Avoid phish-hint words (login, secure, auth) to prevent teaching the
        # model that suspicious subdomains are benign.
        _common_subdomains = [
            "mail", "accounts", "drive", "docs", "calendar", "maps",
            "shop", "store", "blog", "news", "video", "mobile", "m",
            "cdn", "static", "assets", "media", "images", "api",
            "www2", "beta", "dev", "support", "help",
        ]
        rng_sub = random.Random(seed + 2)
        # 3 random subdomain variants per benign domain
        subdomain_variants = [
            u.replace("https://", f"https://{rng_sub.choice(_common_subdomains)}.", 1)
            for _ in range(3)
            for u in benign_urls
            if not u.startswith("https://www.")
        ]
        # Path variants — add realistic paths to benign bare domains so the model
        # learns that paths are not inherently phishing signals.
        # Deliberately excludes phish-hint words (login, secure, etc.) to keep
        # the training signal clean: phish_hints_count > 0 should still correlate
        # with phishing, just not exclusively.
        _common_paths = [
            # ---- plain paths (no query string) ----
            "/", "/index.html", "/index.php", "/home", "/about", "/about-us",
            "/contact", "/contact-us", "/products", "/services", "/news",
            "/blog", "/blog/post/1", "/faq", "/help", "/privacy", "/terms",
            "/page/1", "/page/2", "/category/items", "/article/123",
            "/user/profile", "/settings", "/sitemap.xml", "/robots.txt",
            "/static/main.js", "/assets/style.css", "/images/logo.png",
            "/api/v1/data", "/cdn-cgi/trace",
            # ---- query-string paths (critical: teaches model that ?key=val is benign) ----
            "/search?q=test", "/search?q=hello+world", "/search?q=python+tutorial",
            "/?themeRefresh=1", "/?theme=dark", "/?lang=en", "/?lang=id",
            "/?ref=home", "/?ref=nav", "/?source=nav", "/?source=google",
            "/?tab=readme", "/?tab=issues", "/?tab=code",
            "/?sort=newest", "/?sort=popular", "/?page=1", "/?page=2",
            "/watch?v=abc123", "/watch?v=xyz456&t=30",
            "/view?id=456", "/article?id=789", "/post?slug=hello-world",
            "/products?category=electronics", "/news?page=2&sort=date",
            "/profile?id=12345", "/user?name=john",
            "/?utm_source=google&utm_medium=cpc",
            "/?utm_source=newsletter&utm_campaign=weekly",
            "/api/v1/data?format=json", "/feed?type=rss",
            "/?v=3&q=main", "/?action=view&id=1",
        ]
        rng_path = random.Random(seed + 3)
        # 4 random path variants per benign domain — enough to cover query-string patterns
        path_variants = [
            u.rstrip("/") + rng_path.choice(_common_paths)
            for _ in range(4)
            for u in benign_urls
        ]
        benign_urls = benign_urls + www_variants + subdomain_variants + path_variants

        if max_benign is not None and len(benign_urls) > max_benign:
            rng = random.Random(seed)
            benign_urls = rng.sample(benign_urls, max_benign)
        urls.extend(benign_urls)
        labels.extend([0] * len(benign_urls))
        logger.info(f"Loaded {len(benign_urls):,} benign URLs")
    else:
        logger.warning(f"benign_domains.csv not found in {data_dir}")

    # phishing (label=1) — PhishTank CSV: id, url, phish_detail_url, ...
    phishing_path = data_dir / "phishing_domains.csv"
    if phishing_path.exists():
        count = 0
        with open(phishing_path, encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 1:
                    url = row[1].strip()
                    if url and url.startswith("http"):
                        urls.append(url)
                        labels.append(1)
                        count += 1
        logger.info(f"Loaded {count:,} phishing URLs")
    else:
        logger.warning(f"phishing_domains.csv not found in {data_dir}")

    # malware (label=2) — one URL per line (may be bare domains without scheme)
    malware_path = data_dir / "malware_domains.csv"
    if malware_path.exists():
        count = 0
        with open(malware_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    if not url.startswith(("http://", "https://", "ftp://")):
                        url = "http://" + url
                    urls.append(url)
                    labels.append(2)
                    count += 1
        logger.info(f"Loaded {count:,} malware URLs")
    else:
        logger.warning(f"malware_domains.csv not found in {data_dir}")

    # spam (label=3) — one URL per line (may be bare domains without scheme)
    spam_path = data_dir / "spam_domains.csv"
    if spam_path.exists():
        count = 0
        with open(spam_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    if not url.startswith(("http://", "https://", "ftp://")):
                        url = "http://" + url
                    urls.append(url)
                    labels.append(3)
                    count += 1
        logger.info(f"Loaded {count:,} spam URLs")
    else:
        logger.warning(f"spam_domains.csv not found in {data_dir}")

    logger.info(f"Total dataset: {len(urls):,} URLs")
    return urls, labels


def load_feedback_data(feedback_dir: str | Path) -> tuple[list[str], list[int]]:
    """
    Load all feedback CSVs from *feedback_dir* (e.g. data/feedback/).

    Each CSV must have columns: url, label
    Label values follow the same convention as the main dataset:
        0=benign, 1=phishing, 2=malware, 3=spam

    Currently the pipeline writes false-positive confirmed URLs as label=0
    (benign) via scripts/ingest_false_positives.py.

    Returns an empty pair if the directory does not exist or contains no CSVs.
    """
    feedback_dir = Path(feedback_dir)
    urls: list[str] = []
    labels: list[int] = []

    if not feedback_dir.exists():
        logger.debug(f"Feedback directory not found: {feedback_dir} — skipping")
        return urls, labels

    csv_files = sorted(feedback_dir.glob("*.csv"))
    if not csv_files:
        logger.debug(f"No CSV files in {feedback_dir} — skipping")
        return urls, labels

    for csv_path in csv_files:
        count = 0
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url", "").strip()
                label_raw = row.get("label", "").strip()
                if not url or not label_raw:
                    continue
                try:
                    label = int(label_raw)
                except ValueError:
                    logger.warning(f"Non-integer label '{label_raw}' in {csv_path} — skipping row")
                    continue
                urls.append(url)
                labels.append(label)
                count += 1
        logger.info(f"Loaded {count:,} feedback rows from {csv_path.name}")

    logger.info(f"Total feedback rows: {len(urls):,}")
    return urls, labels


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
