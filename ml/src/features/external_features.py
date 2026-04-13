"""
External / network-based features — 7 features.

These features query DNS, WHOIS, and follow HTTP redirects to extract signals
that cannot be derived from the URL string or HTML alone.

Important
---------
- All lookups are performed with timeouts and return safe defaults on failure.
- At training time on URL-only datasets (CIC-Bell-DNS2021) these features are
  not computed by default (all zeros / -1).  Pass compute=True to enable them.
- At inference time in the backend they are computed with a short timeout.

Feature semantics
-----------------
  has_dns_record          1 if the domain has a DNS A/AAAA record, else 0.
                          New phishing domains often have no DNS (or
                          recently-registered records).

  domain_age_days         Age of the domain in days from WHOIS creation date.
                          -1 if WHOIS unavailable. Phishing domains are often
                          very young (< 30 days).

  registration_length_days Days between today and WHOIS expiry date.
                          -1 if unavailable. Phishing domains are often
                          registered for only 1 year (365 days).

  whois_registered        1 if a WHOIS record exists, 0 if not.

  redirect_count          Number of HTTP redirects followed before reaching
                          final response. 0 if no redirects or fetch failed.

  has_redirect            1 if any HTTP redirect occurred.

  has_external_redirect   1 if a redirect crossed to a different domain.
"""

from __future__ import annotations

import re
import socket
from datetime import datetime
from urllib.parse import urlparse

from ml.src.features.ssrf_guard import validate_url

# ---------------------------------------------------------------------------
# Default "unknown" values
# ---------------------------------------------------------------------------
_UNKNOWN_AGE  = -1
_UNKNOWN_DAYS = -1


def _zero_features() -> dict:
    return {
        "has_dns_record":           0,
        "domain_age_days":          _UNKNOWN_AGE,
        "registration_length_days": _UNKNOWN_DAYS,
        "whois_registered":         0,
        "redirect_count":           0,
        "has_redirect":             0,
        "has_external_redirect":    0,
    }


def extract_external_features(
    url: str,
    timeout: float = 5.0,
    compute: bool = True,
) -> dict:
    """
    Extract 7 external features for *url*.

    Parameters
    ----------
    url:     The URL to analyse (must include scheme).
    timeout: Per-lookup network timeout in seconds.
    compute: If False, returns all-zero features immediately (for training on
             URL-only datasets where network lookups are too slow / not needed).

    Returns
    -------
    dict with exactly 7 numeric features.
    """
    if not compute:
        return _zero_features()

    # URL length guard
    if len(url) > 2048:
        return _zero_features()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # SSRF guard — validate before making any outbound request
    if validate_url(url) is None:
        return _zero_features()

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return _zero_features()

    feats = _zero_features()

    # ------------------------------------------------------------------ #
    # DNS record check (fast — single socket call)                        #
    # ------------------------------------------------------------------ #
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        feats["has_dns_record"] = 1
    except (socket.gaierror, OSError):
        feats["has_dns_record"] = 0

    # ------------------------------------------------------------------ #
    # WHOIS: domain age and registration length                           #
    # ------------------------------------------------------------------ #
    try:
        import whois  # python-whois package
        w = whois.whois(hostname)
        today = datetime.utcnow()

        creation = w.creation_date
        if isinstance(creation, list):
            creation = min(creation)
        if creation and isinstance(creation, datetime):
            feats["domain_age_days"] = max(0, (today - creation).days)
            feats["whois_registered"] = 1

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = min(expiry)
        if expiry and isinstance(expiry, datetime):
            feats["registration_length_days"] = max(0, (expiry - today).days)
    except Exception:
        # WHOIS unavailable, rate-limited, or domain not found — use defaults
        pass

    # ------------------------------------------------------------------ #
    # HTTP redirect chain (SSRF-safe: follow redirects manually)           #
    # ------------------------------------------------------------------ #
    _MAX_REDIRECTS = 5
    try:
        import requests as _requests
        resp = _requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishScamSense/1.0)"},
        )
        redirect_count = 0
        seen_external = False
        current_url = url

        for _ in range(_MAX_REDIRECTS):
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("Location", "")
            if not location:
                break
            # Validate redirect target through SSRF guard
            if validate_url(location) is None:
                break
            redirect_count += 1
            redir_host = (urlparse(location).hostname or "").lower()
            if _registrable(redir_host) != _registrable(hostname):
                seen_external = True
            current_url = location
            resp = _requests.get(
                location,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PhishScamSense/1.0)"},
            )

        feats["redirect_count"] = redirect_count
        feats["has_redirect"]   = 1 if redirect_count > 0 else 0
        feats["has_external_redirect"] = 1 if seen_external else 0
    except Exception:
        pass

    assert len(feats) == 7, f"External feature count mismatch: expected 7, got {len(feats)}"
    return feats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _registrable(hostname: str) -> str:
    """Return the last two dot-separated labels (best-effort registrable domain)."""
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
