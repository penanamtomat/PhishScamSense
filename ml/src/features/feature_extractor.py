"""
Combined 88-feature extractor for PhishScamSense.

Feature composition
-------------------
  URL features     (57)  — always computed, no network I/O
  Content features (24)  — computed when HTML is provided (browser extension)
  External features ( 7) — computed when enabled (DNS/WHOIS/HTTP)
                    ---
  Total            (88)

Usage
-----
    from ml.src.features.feature_extractor import extract_features

    # URL-only (fast, offline):
    feats = extract_features(url)

    # URL + page content (browser extension sends HTML):
    feats = extract_features(url, html=page_html)

    # Full 88 features including DNS/WHOIS/HTTP:
    feats = extract_features(url, html=page_html, compute_external=True)

Training notes
--------------
The CIC-Bell-DNS2021 dataset contains URLs only (no page HTML).  For initial
training, content features default to 0 and external features are disabled.
XGBoost will assign zero importance to constant-zero features; they become
meaningful once the extension passes page HTML at inference time.

To fully exploit content + external features, train on a dataset where page
HTML has been pre-fetched.  The training script accepts --fetch-content which
fetches each page and extracts all 88 features.
"""

from __future__ import annotations

from .url_features import extract_url_features
from .content_features import extract_content_features
from .external_features import extract_external_features

FEATURE_COUNT = 88  # 57 + 24 + 7


def extract_features(
    url: str,
    html: str | None = None,
    compute_external: bool = False,
    external_timeout: float = 5.0,
) -> dict:
    """
    Extract all 88 features for *url*.

    Parameters
    ----------
    url:              The URL to analyse.
    html:             Raw HTML string of the loaded page (optional).
                      When provided, content features are computed.
                      When None, content features are all 0.
    compute_external: Whether to perform DNS/WHOIS/HTTP lookups.
                      Disabled by default for training speed; enable for
                      high-accuracy inference.
    external_timeout: Per-lookup timeout in seconds (used when compute_external=True).

    Returns
    -------
    Ordered dict with exactly 88 numeric features.
    """
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://", "ftp://")):
        url_norm = "http://" + url
    else:
        url_norm = url

    hostname = (urlparse(url_norm).hostname or "").lower()

    url_feats      = extract_url_features(url)
    content_feats  = extract_content_features(html, hostname=hostname)
    external_feats = extract_external_features(
        url_norm,
        timeout=external_timeout,
        compute=compute_external,
    )

    combined = {**url_feats, **content_feats, **external_feats}
    assert len(combined) == FEATURE_COUNT, (
        f"Feature count mismatch: expected {FEATURE_COUNT}, got {len(combined)}"
    )
    return combined
