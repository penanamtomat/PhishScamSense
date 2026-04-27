# URL Shortener Deep Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a URL shortener is submitted (e.g. `bit.ly/xxx`), resolve it to the final destination URL, attempt to fetch that page's HTML, then run the full ML pipeline on the final URL + HTML instead of the uninformative shortener URL.

**Architecture:** A new `shortener_expander.py` module handles URL resolution and HTML fetch with a graceful A2 fallback (URL-only if HTML fetch fails). `MLPredictor.predict()` calls the expander when it detects a shortener domain. The response schema gains an optional `shortener_analysis` field (non-breaking).

**Tech Stack:** Python 3.11, `requests`, existing `ssrf_guard.validate_url`, `SHORTENING_RE` from `url_features.py`, Pydantic v2, pytest

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `ml/src/features/shortener_expander.py` | `ExpandedURL` dataclass, `is_shortener_url()`, `expand_shortener_url()` |
| Create | `backend/tests/test_shortener_expander.py` | Unit tests for expander module |
| Modify | `backend/app/schemas/prediction.py` | Add `ShortenerAnalysis` model + field on `PredictionResponse` |
| Modify | `backend/app/services/ml_predictor.py` | Call expander before inference, propagate result |
| Modify | `backend/app/api/routes/predict.py` | Pass `shortener_analysis` to response |
| Modify | `backend/tests/test_predict.py` | Tests for shortener URL response field |

---

## Task 1: Create `shortener_expander.py` module

**Files:**
- Create: `ml/src/features/shortener_expander.py`

- [ ] **Step 1: Create the module**

```python
# ml/src/features/shortener_expander.py
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
```

- [ ] **Step 2: Verify the module imports cleanly (no test yet)**

Run from project root:
```bash
cd D:/PhishScamSense
python -c "from ml.src.features.shortener_expander import is_shortener_url, expand_shortener_url, ExpandedURL; print('OK')"
```
Expected output: `OK`

- [ ] **Step 3: Commit**

```bash
git add ml/src/features/shortener_expander.py
git commit -m "feat(ml): add shortener_expander module for URL resolution and HTML fetch"
```

---

## Task 2: Unit tests for `shortener_expander.py`

**Files:**
- Create: `backend/tests/test_shortener_expander.py`

- [ ] **Step 1: Write the tests**

```python
# backend/tests/test_shortener_expander.py
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
    """One redirect hop, HTML fetch succeeds."""
    final_html = "<html><body>Rekrutmen BI</body></html>"
    mock_get.side_effect = [
        _make_redirect_response("https://rekrutmen-bi.id/pkwt2026/beranda"),
        _make_ok_response(final_html),
    ]

    result = expand_shortener_url("https://bit.ly/4doXuXd")

    assert result.final_url == "https://rekrutmen-bi.id/pkwt2026/beranda"
    assert result.hop_count == 1
    assert result.fetch_success is True
    assert "Rekrutmen BI" in result.html


@patch("ml.src.features.shortener_expander.validate_url", return_value="https://example.com/page")
@patch("requests.get")
def test_expand_two_hops(mock_get, _mock_validate):
    """Two redirect hops are counted correctly."""
    mock_get.side_effect = [
        _make_redirect_response("https://intermediate.example.com/r"),
        _make_redirect_response("https://example.com/page"),
        _make_ok_response("<html>Final</html>"),
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
    mock_get.side_effect = [
        _make_redirect_response("https://example.com"),
        large_resp,
    ]

    result = expand_shortener_url("https://bit.ly/large")

    assert result.fetch_success is True
    assert len(result.html.encode("utf-8")) <= 2 * 1024 * 1024 + 100  # small decode overhead
```

- [ ] **Step 2: Run the tests to verify they all pass**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/test_shortener_expander.py -v
```

Expected: all 11 tests PASS

- [ ] **Step 3: Commit**

```bash
git add backend/tests/test_shortener_expander.py
git commit -m "test(ml): unit tests for shortener_expander module"
```

---

## Task 3: Add `ShortenerAnalysis` to response schema

**Files:**
- Modify: `backend/app/schemas/prediction.py`

- [ ] **Step 1: Write a failing test first**

Add to `backend/tests/test_predict.py` (append to the file):

```python
def test_predict_shortener_url_includes_shortener_analysis(client, mock_predictor):
    """Shortener URLs include shortener_analysis field in response."""
    mock_predictor.predict.return_value = {
        **MOCK_BENIGN_RESULT,
        "shortener_analysis": {
            "detected": True,
            "final_url": "https://rekrutmen-bi.id/pkwt2026/beranda",
            "hop_count": 1,
            "html_fetched": True,
        },
    }

    resp = client.post("/api/v1/predict", json={"url": "https://bit.ly/4doXuXd"})

    assert resp.status_code == 200
    body = resp.json()
    sa = body.get("shortener_analysis")
    assert sa is not None
    assert sa["detected"] is True
    assert sa["final_url"] == "https://rekrutmen-bi.id/pkwt2026/beranda"
    assert sa["hop_count"] == 1
    assert sa["html_fetched"] is True


def test_predict_non_shortener_url_has_no_shortener_analysis(client, mock_predictor):
    """Non-shortener URLs do not include shortener_analysis field."""
    mock_predictor.predict.return_value = MOCK_BENIGN_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": "https://www.google.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body.get("shortener_analysis") is None
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/test_predict.py::test_predict_shortener_url_includes_shortener_analysis tests/test_predict.py::test_predict_non_shortener_url_has_no_shortener_analysis -v
```

Expected: FAIL — `shortener_analysis` not yet in schema

- [ ] **Step 3: Update `prediction.py` schema**

Replace the entire contents of `backend/app/schemas/prediction.py`:

```python
import re

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 2048

# URL format: must start with http:// or https:// and have a valid hostname
_URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}"
    r"(?::\d{1,5})?"
    r"(?:/[^\s]*)?$"
)


class PredictionRequest(BaseModel):
    url: str = Field(..., max_length=MAX_URL_LENGTH)
    html: str | None = Field(default=None, max_length=1_000_000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH}")
        if not _URL_PATTERN.match(v):
            raise ValueError(
                "URL must start with http:// or https:// and have a valid hostname"
            )
        # Block dangerous schemes
        lower = v.lower()
        if "javascript:" in lower or "data:" in lower:
            raise ValueError("URL scheme not allowed")
        return v


class ShortenerAnalysis(BaseModel):
    detected: bool
    final_url: str
    hop_count: int
    html_fetched: bool


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    label: int = 0
    threat_type: str = "benign"
    features: dict | None = None
    shortener_analysis: ShortenerAnalysis | None = None
```

- [ ] **Step 4: Run the new tests — still failing (route not updated yet)**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/test_predict.py::test_predict_shortener_url_includes_shortener_analysis tests/test_predict.py::test_predict_non_shortener_url_has_no_shortener_analysis -v
```

Expected: `test_predict_non_shortener_url_has_no_shortener_analysis` PASSES (None by default), `test_predict_shortener_url_includes_shortener_analysis` still FAILS (route doesn't pass field yet).

- [ ] **Step 5: Commit schema**

```bash
git add backend/app/schemas/prediction.py backend/tests/test_predict.py
git commit -m "feat(schema): add ShortenerAnalysis model and optional field on PredictionResponse"
```

---

## Task 4: Wire expander into `MLPredictor.predict()`

**Files:**
- Modify: `backend/app/services/ml_predictor.py`

- [ ] **Step 1: Add import for the expander at the top of `ml_predictor.py`**

After the existing `from ml.src.features.whitelist import is_whitelisted` line (line 28), add:

```python
from ml.src.features.shortener_expander import (
    ExpandedURL,
    expand_shortener_url,
    is_shortener_url,
)
```

- [ ] **Step 2: Update `MLPredictor.predict()` to call the expander**

The current `predict()` method starts with the whitelist check (around line 200). Add shortener expansion immediately after the whitelist check, before feature extraction.

Find this block in `ml_predictor.py`:

```python
        if is_whitelisted(url):
            return {
                "phishing": False,
                "confidence": 1.0,
                "label": 0,
                "threat_type": "benign",
                "features": {},
                "whitelisted": True,
            }

        np = self._np
        features = self._extract_features(url, html=html, compute_external=False)
```

Replace with:

```python
        if is_whitelisted(url):
            return {
                "phishing": False,
                "confidence": 1.0,
                "label": 0,
                "threat_type": "benign",
                "features": {},
                "whitelisted": True,
            }

        shortener_analysis: dict | None = None
        if is_shortener_url(url):
            expanded = expand_shortener_url(url)
            url = expanded.final_url
            html = expanded.html  # None triggers A2 fallback (URL-only) automatically
            shortener_analysis = {
                "detected": True,
                "final_url": expanded.final_url,
                "hop_count": expanded.hop_count,
                "html_fetched": expanded.fetch_success,
            }

        np = self._np
        features = self._extract_features(url, html=html, compute_external=False)
```

- [ ] **Step 3: Propagate `shortener_analysis` in the return dict**

Find the final return statement in `predict()`:

```python
        return {
            "phishing": pred_class != 0,
            "confidence": float(proba[pred_class]),
            "label": pred_class,
            "threat_type": CLASS_NAMES[pred_class],
            "features": features,
        }
```

Replace with:

```python
        result: dict = {
            "phishing": pred_class != 0,
            "confidence": float(proba[pred_class]),
            "label": pred_class,
            "threat_type": CLASS_NAMES[pred_class],
            "features": features,
        }
        if shortener_analysis is not None:
            result["shortener_analysis"] = shortener_analysis
        return result
```

- [ ] **Step 4: Run existing `test_ml_predictor.py` to confirm no regressions**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/test_ml_predictor.py -v
```

Expected: all existing tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/ml_predictor.py
git commit -m "feat(predictor): expand shortener URLs before ML inference"
```

---

## Task 5: Update predict route to pass `shortener_analysis` through

**Files:**
- Modify: `backend/app/api/routes/predict.py`

- [ ] **Step 1: Update the `PredictionResponse` construction in `predict_url()`**

Find the return statement in `backend/app/api/routes/predict.py`:

```python
    return PredictionResponse(
        phishing=result["phishing"],
        confidence=result["confidence"],
        label=result["label"],
        threat_type=result["threat_type"],
        features=result.get("features") if include_features else None,
    )
```

Replace with:

```python
    sa_data = result.get("shortener_analysis")
    shortener_analysis = None
    if sa_data is not None:
        from app.schemas.prediction import ShortenerAnalysis
        shortener_analysis = ShortenerAnalysis(**sa_data)

    return PredictionResponse(
        phishing=result["phishing"],
        confidence=result["confidence"],
        label=result["label"],
        threat_type=result["threat_type"],
        features=result.get("features") if include_features else None,
        shortener_analysis=shortener_analysis,
    )
```

- [ ] **Step 2: Run all new predict tests**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/test_predict.py -v
```

Expected: all tests PASS including the two new shortener tests

- [ ] **Step 3: Run the full test suite**

```bash
cd D:/PhishScamSense/backend
python -m pytest tests/ -v
```

Expected: all tests PASS, no regressions

- [ ] **Step 4: Commit**

```bash
git add backend/app/api/routes/predict.py
git commit -m "feat(api): pass shortener_analysis through predict route response"
```

---

## Task 6: Commit spec and plan docs

- [ ] **Step 1: Commit docs**

```bash
git add docs/superpowers/specs/2026-04-27-url-shortener-deep-analysis-design.md
git add docs/superpowers/plans/2026-04-27-url-shortener-deep-analysis.md
git commit -m "docs: add URL shortener deep analysis spec and implementation plan"
```

---

## Self-Review Notes

- **Spec coverage check:** All 4 spec sections covered — Detection (Task 4 `is_shortener_url`), Resolution+Fetch (Task 1 `expand_shortener_url`), Response schema (Task 3), Error handling table (Tasks 1+4 — all fallback cases handled by `except Exception: pass` and `html=None`)
- **No placeholders:** All steps contain actual code
- **Type consistency:** `ExpandedURL` defined in Task 1, imported in Task 4. `ShortenerAnalysis` defined in Task 3, imported in Task 5. `shortener_analysis` dict key consistent across Tasks 4 and 5.
- **Import note:** The `ShortenerAnalysis` import in `predict.py` is done inline to avoid circular import risk (schemas → services is fine; services → schemas is fine too, but keeping it local is safer).
