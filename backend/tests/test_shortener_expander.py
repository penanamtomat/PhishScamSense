"""
Unit tests for ml.src.features.shortener_expander.

Network calls are fully mocked — tests never make real HTTP requests.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ml.src.features.shortener_expander import (
    ExpandedURL,
    expand_shortener_url,
    is_shortener_url,
)


# ---------------------------------------------------------------------------
# is_shortener_url
# ---------------------------------------------------------------------------

def test_is_shortener_url_detects_bitly():
    assert is_shortener_url("https://bit.ly/4doXuXd") is True


def test_is_shortener_url_detects_tco():
    assert is_shortener_url("https://t.co/abc123") is True


def test_is_shortener_url_detects_tinyurl():
    assert is_shortener_url("https://tinyurl.com/xyz") is True


def test_is_shortener_url_rejects_normal_url():
    assert is_shortener_url("https://rekrutmen-bi.id/pkwt2026/beranda") is False


def test_is_shortener_url_rejects_google():
    assert is_shortener_url("https://www.google.com/search?q=test") is False


# ---------------------------------------------------------------------------
# expand_shortener_url — happy path (redirect + HTML fetch)
# ---------------------------------------------------------------------------

def _make_redirect_response(location: str, status: int = 301) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Location": location}
    return resp


def _make_ok_response(html: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.content = html.encode("utf-8")
    return resp


@patch("ml.src.features.shortener_expander.validate_url", return_value="https://rekrutmen-bi.id/pkwt2026/beranda")
@patch("requests.get")
def test_expand_follows_redirect_and_fetches_html(mock_get, _mock_validate):
    """One redirect hop, HTML fetch succeeds.

    The redirect loop makes one extra GET at the final URL (to check whether
    IT also redirects) before breaking — so 3 responses are needed:
      1. bit.ly → 301 to rekrutmen-bi.id
      2. rekrutmen-bi.id → 200 (breaks loop, not a redirect)
      3. rekrutmen-bi.id → 200 with HTML (the actual content fetch)
    """
    final_html = "<html><body>Rekrutmen BI</body></html>"
    mock_get.side_effect = [
        _make_redirect_response("https://rekrutmen-bi.id/pkwt2026/beranda"),
        _make_ok_response(""),          # loop-break: final URL is not a redirect
        _make_ok_response(final_html),  # HTML fetch
    ]

    result = expand_shortener_url("https://bit.ly/4doXuXd")

    assert result.final_url == "https://rekrutmen-bi.id/pkwt2026/beranda"
    assert result.hop_count == 1
    assert result.fetch_success is True
    assert "Rekrutmen BI" in result.html


@patch("ml.src.features.shortener_expander.validate_url", return_value="https://example.com/page")
@patch("requests.get")
def test_expand_two_hops(mock_get, _mock_validate):
    """Two redirect hops are counted correctly.

    Responses needed:
      1. bit.ly → 301 to intermediate
      2. intermediate → 301 to example.com/page
      3. example.com/page → 200 (breaks loop)
      4. example.com/page → 200 with HTML (content fetch)
    """
    mock_get.side_effect = [
        _make_redirect_response("https://intermediate.example.com/r"),
        _make_redirect_response("https://example.com/page"),
        _make_ok_response(""),                      # loop-break
        _make_ok_response("<html>Final</html>"),    # HTML fetch
    ]

    result = expand_shortener_url("https://bit.ly/short")

    assert result.hop_count == 2
    assert result.final_url == "https://example.com/page"
    assert result.fetch_success is True


# ---------------------------------------------------------------------------
# expand_shortener_url — A2 fallback (HTML fetch fails)
# ---------------------------------------------------------------------------

@patch("ml.src.features.shortener_expander.validate_url", return_value="https://example.com/page")
@patch("requests.get")
def test_expand_html_fetch_timeout_returns_url_only(mock_get, _mock_validate):
    """Redirect resolves but HTML fetch times out — fetch_success=False, html=None."""
    import requests as req
    mock_get.side_effect = [
        _make_redirect_response("https://example.com/page"),
        req.exceptions.Timeout(),
    ]

    result = expand_shortener_url("https://bit.ly/short")

    assert result.final_url == "https://example.com/page"
    assert result.hop_count == 1
    assert result.fetch_success is False
    assert result.html is None


@patch("ml.src.features.shortener_expander.validate_url", return_value="https://example.com/page")
@patch("requests.get")
def test_expand_html_fetch_non_2xx_returns_url_only(mock_get, _mock_validate):
    """Redirect resolves but HTML fetch returns 403 — fetch_success=False."""
    error_resp = MagicMock()
    error_resp.status_code = 403
    mock_get.side_effect = [
        _make_redirect_response("https://example.com/page"),
        error_resp,
    ]

    result = expand_shortener_url("https://bit.ly/short")

    assert result.fetch_success is False
    assert result.html is None


# ---------------------------------------------------------------------------
# expand_shortener_url — SSRF guard blocks redirect
# ---------------------------------------------------------------------------

@patch("ml.src.features.shortener_expander.validate_url", return_value=None)
@patch("requests.get")
def test_expand_ssrf_blocked_falls_back_to_original(mock_get, _mock_validate):
    """If SSRF guard blocks the redirect target, final_url stays as original."""
    mock_get.return_value = _make_redirect_response("http://192.168.1.1/admin")

    result = expand_shortener_url("https://bit.ly/internal")

    assert result.final_url == "https://bit.ly/internal"
    assert result.hop_count == 0
    assert result.fetch_success is False


# ---------------------------------------------------------------------------
# expand_shortener_url — network completely down
# ---------------------------------------------------------------------------

@patch("requests.get", side_effect=Exception("Network error"))
def test_expand_network_error_returns_original_url(mock_get):
    """All network errors are swallowed — returns original URL gracefully."""
    result = expand_shortener_url("https://bit.ly/broken")

    assert result.final_url == "https://bit.ly/broken"
    assert result.hop_count == 0
    assert result.fetch_success is False
    assert result.html is None


# ---------------------------------------------------------------------------
# ExpandedURL respects 2 MB HTML cap
# ---------------------------------------------------------------------------

@patch("ml.src.features.shortener_expander.validate_url", return_value="https://example.com")
@patch("requests.get")
def test_expand_truncates_html_at_2mb(mock_get, _mock_validate):
    """HTML larger than 2 MB is truncated before decoding."""
    three_mb = b"A" * (3 * 1024 * 1024)
    large_resp = MagicMock()
    large_resp.status_code = 200
    large_resp.content = three_mb
    non_redirect = MagicMock()
    non_redirect.status_code = 200
    non_redirect.content = b""
    mock_get.side_effect = [
        _make_redirect_response("https://example.com"),
        non_redirect,   # loop-break: final URL is not a redirect
        large_resp,     # HTML fetch with 3 MB payload
    ]

    result = expand_shortener_url("https://bit.ly/large")

    assert result.fetch_success is True
    assert len(result.html.encode("utf-8")) <= 2 * 1024 * 1024 + 100
