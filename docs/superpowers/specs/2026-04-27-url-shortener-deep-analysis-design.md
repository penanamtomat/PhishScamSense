# URL Shortener Deep Analysis — Design Spec

**Date:** 2026-04-27  
**Status:** Approved  
**Scope:** Backend only — no model retraining, no extension changes required

---

## Problem

When a user submits a URL shortener (e.g., `bit.ly/4doXuQd`), the ML pipeline analyzes
the shortener domain itself — which has no meaningful lexical or content signal. This causes
frequent false negatives: malicious pages hidden behind legitimate shortener domains are
classified as benign because the shortener URL looks clean.

---

## Solution

When a shortener URL is detected, the backend:
1. Follows HTTP redirects to resolve the final destination URL
2. Attempts to fetch the HTML of the final URL (best-effort, 5s timeout)
3. Runs the full ML prediction pipeline on the final URL + fetched HTML
4. Falls back to URL-only analysis if HTML fetch fails (graceful degradation)

No model retraining is required. The same ML pipeline runs on a more informative input.

---

## Architecture

### Detection

Shortener detection reuses the existing `is_shortening_service` flag logic in
`ml/src/features/url_features.py`. A known shortener domain set is extracted into a
shared constant so both the feature extractor and the new expander module can reference it
without duplication.

### New Module: `ml/src/features/shortener_expander.py`

Responsible for resolution and HTML fetch. Returns an `ExpandedURL` dataclass.

```python
@dataclass
class ExpandedURL:
    final_url: str        # URL after following all redirects
    html: str | None      # Fetched HTML, None if fetch failed or timed out
    hop_count: int        # Number of redirect hops followed (0–5)
    fetch_success: bool   # True if HTML was successfully retrieved
```

**Resolution logic:**
- Reuses the redirect-following pattern from `external_features.py`
- SSRF guard (`validate_url`) applied at every hop before following
- Max 5 redirect hops (hard limit, consistent with existing behavior)
- If final URL fails SSRF guard → return original URL, hop_count=0, html=None

**HTML fetch logic (A1):**
- `requests.get(final_url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})` 
- Accept only 2xx responses; any other status → html=None (A2 fallback)
- Truncate response at 2MB (consistent with existing `PredictionRequest` HTML limit)
- Any exception (timeout, connection error, SSL error) → html=None (A2 fallback)
- No retry — single attempt only

### Integration Point: `MLPredictor.predict()`

Before running the existing prediction logic, check if the input URL is a shortener.
If yes, call `expand_shortener_url(url)` and substitute `final_url` + `html` into
the pipeline. The existing HTML sent by the extension (if any) is discarded for shortener
URLs — server-fetched HTML of the final destination is more relevant.

```
predict(url, html_from_extension)
  └─ is_shortener(url)?
       YES → expanded = expand_shortener_url(url)
             run pipeline with (expanded.final_url, expanded.html)
       NO  → run pipeline with (url, html_from_extension)
```

### Response Schema Change

`PredictionResponse` gains an optional field `shortener_analysis`. It is only present
when a shortener was detected; absent otherwise (no breaking change).

```json
{
  "phishing": false,
  "confidence": 0.97,
  "threat_type": "benign",
  "shortener_analysis": {
    "detected": true,
    "final_url": "https://rekrutmen-bi.id/pkwt2026/beranda",
    "hop_count": 2,
    "html_fetched": true
  }
}
```

---

## Data Flow

```
User submits: bit.ly/4doXuXd
  │
  ├─ Whitelist check → not whitelisted
  │
  ├─ is_shortener("bit.ly") → True
  │
  ├─ expand_shortener_url("bit.ly/4doXuXd")
  │    ├─ Follow redirects (SSRF-guarded, max 5)
  │    │    → final_url = "https://rekrutmen-bi.id/pkwt2026/beranda"
  │    ├─ Fetch HTML (5s timeout, browser User-Agent)
  │    │    → success: html = "<html>...</html>"
  │    │    → failure: html = None
  │    └─ return ExpandedURL(final_url, html, hop_count=2, fetch_success=True)
  │
  ├─ predict(final_url="https://rekrutmen-bi.id/...", html=html)
  │    ├─ extract_url_features(final_url)   → 57 features
  │    ├─ extract_content_features(html)    → 24 features (or zeros if html=None)
  │    ├─ extract_external_features(...)    → 7 features
  │    └─ ML inference → verdict
  │
  └─ Response includes shortener_analysis metadata
```

---

## Error Handling

| Condition | Behavior |
|---|---|
| Final URL is private IP / SSRF target | Use original shortener URL for prediction |
| DNS resolution fails for shortener | Use original shortener URL for prediction |
| HTML fetch timeout (>5s) | Predict on final URL without HTML (A2 fallback) |
| HTML fetch returns non-2xx | Predict on final URL without HTML (A2 fallback) |
| Final URL is itself a shortener | Follow redirect chain (counted in max 5 hops) |
| Final URL is whitelisted | Return whitelisted=True immediately, skip inference |
| Extension sends html for a shortener URL | Discarded; server-fetched HTML takes precedence |

---

## Files Changed

| File | Change |
|---|---|
| `ml/src/features/shortener_expander.py` | New — `ExpandedURL` dataclass + `expand_shortener_url()` |
| `ml/src/features/url_features.py` | Extract `SHORTENER_DOMAINS` set as module-level constant |
| `backend/app/services/ml_predictor.py` | Call expander before inference when shortener detected |
| `backend/app/schemas/prediction.py` | Add optional `shortener_analysis` field to response schema |

---

## Out of Scope

- Extension UI changes (showing redirect chain to user) — separate feature
- JavaScript rendering of final page (Playwright/Puppeteer) — future enhancement
- Caching resolved shortener URLs — future optimization
- Retraining the model with shortener-expanded dataset — future improvement
