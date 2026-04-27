"""
URL shortener expansion — resolve final destination and fetch HTML.

For known shortener domains (bit.ly, t.co, etc.) the shortener URL itself
carries no lexical signal.  This module follows the redirect chain to find
the real destination URL, then attempts a best-effort HTML fetch so the full
88-feature pipeline can run on the actual target page.

If HTML fetch fails or times out the caller should fall back to URL-only
analysis (A2 fallback) — this module never raises, it always returns an
ExpandedURL with fetch_success=False in that case.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ml.src.features.ssrf_guard import validate_url
from ml.src.features.url_features import SHORTENING_RE

_MAX_REDIRECTS = 5
_FETCH_TIMEOUT = 5.0
_MAX_HTML_BYTES = 2 * 1024 * 1024  # 2 MB — matches PredictionRequest.html limit
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class ExpandedURL:
    final_url: str       # URL after following all redirects
    html: str | None     # Fetched HTML, None if fetch failed or timed out
    hop_count: int       # Number of redirect hops followed (0–5)
    fetch_success: bool  # True if HTML was successfully retrieved


def is_shortener_url(url: str) -> bool:
    """Return True if *url*'s hostname matches a known shortener domain."""
    hostname = (urlparse(url).hostname or "").lower()
    return bool(SHORTENING_RE.search(hostname))


def expand_shortener_url(url: str) -> ExpandedURL:
    """
    Resolve *url* through its redirect chain and attempt to fetch the final page HTML.

    Never raises — all network errors produce ExpandedURL with fetch_success=False
    and final_url set to whatever hop was reached before the error.
    """
    import requests  # lazy import — not available during training

    final_url = url
    hop_count = 0

    # ------------------------------------------------------------------ #
    # Step 1: follow redirect chain (SSRF-safe, max _MAX_REDIRECTS hops)  #
    # ------------------------------------------------------------------ #
    try:
        current = url
        for _ in range(_MAX_REDIRECTS):
            resp = requests.get(
                current,
                timeout=_FETCH_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": _USER_AGENT},
            )
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("Location", "")
            if not location:
                break
            # Resolve relative redirects (e.g. "/path") to absolute URLs
            if location.startswith("/"):
                parsed = urlparse(current)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            # SSRF guard — validate each hop before following
            if validate_url(location) is None:
                break
            hop_count += 1
            final_url = location
            current = location
    except Exception:
        pass

    # ------------------------------------------------------------------ #
    # Step 2: fetch HTML of final destination (best-effort, A1 path)      #
    # ------------------------------------------------------------------ #
    html: str | None = None
    fetch_success = False

    try:
        resp = requests.get(
            final_url,
            timeout=_FETCH_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
        )
        if resp.status_code // 100 == 2:
            raw = resp.content[:_MAX_HTML_BYTES]
            html = raw.decode("utf-8", errors="replace")
            fetch_success = True
    except Exception:
        pass

    return ExpandedURL(
        final_url=final_url,
        html=html,
        hop_count=hop_count,
        fetch_success=fetch_success,
    )
