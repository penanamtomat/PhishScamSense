"""
Content-based feature extraction — 24 features.

Parses the raw HTML of a page (already loaded by the browser) to extract
DOM-level signals that URL-only analysis cannot see:
  - Link structure (internal vs. external vs. null hrefs)
  - Form behaviour (external actions, mailto targets)
  - Resource loading (external CSS, media, favicons)
  - Suspicious JS (onmouseover, popup, right-click disabling)
  - Page identity (title, copyright)

All features return 0 (safe default) when *html* is None or empty, so the
training pipeline can call this module even when page content is unavailable.
The XGBoost model will learn to ignore constant-zero features during training
on URL-only datasets; these features become active once the extension passes
page HTML.

Usage
-----
    from ml.src.features.content_features import extract_content_features
    feats = extract_content_features(html_string, hostname="example.com")
"""

from __future__ import annotations

import re

# BeautifulSoup is an optional dependency; degrade gracefully if absent.
try:
    from bs4 import BeautifulSoup, Tag
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

# ---------------------------------------------------------------------------
# Null-link patterns (from Hannousse 2021 reference implementation)
# ---------------------------------------------------------------------------
_NULL_HREFS = frozenset({
    "", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
    "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;",
    "javascript", "javascript:void(0)", "javascript:void(0);",
})

_NULL_CONTENT_COUNT = 24  # number of features in this module


def _zero_features() -> dict:
    """Return all-zero content features (safe fallback)."""
    return {
        # Hyperlink structure
        "nb_hyperlinks":               0,
        "ratio_internal_hyperlinks":   0.0,
        "ratio_external_hyperlinks":   0.0,
        "ratio_null_hyperlinks":       0.0,
        # CSS / resources
        "nb_external_css":             0,
        # Redirections / errors (approximated from static HTML)
        "ratio_internal_redirections": 0.0,
        "ratio_external_redirections": 0.0,
        "ratio_internal_errors":       0.0,
        "ratio_external_errors":       0.0,
        # Form / login behaviour
        "has_login_form":              0,
        "has_external_favicon":        0,
        "submits_to_email":            0,
        # Media
        "pct_internal_media":          0.0,
        "pct_external_media":          0.0,
        # Page identity
        "has_empty_title":             0,
        "pct_unsafe_anchors":          0.0,
        "pct_internal_links_in_tags":  0.0,
        # Suspicious patterns
        "has_null_form_handler":       0,
        "has_iframe":                  0,
        "has_onmouseover":             0,
        "has_popup_window":            0,
        "right_click_disabled":        0,
        "domain_not_in_title":         0,
        "domain_not_in_copyright":     0,
    }


def extract_content_features(html: str | None, hostname: str = "") -> dict:
    """
    Extract 24 content-based features from raw page HTML.

    Parameters
    ----------
    html:     Raw HTML string (as returned by requests.text or from the extension).
    hostname: The page's hostname (used to distinguish internal vs. external links).

    Returns
    -------
    dict with 24 numeric features (int or float).
    """
    if not html or not _BS4_AVAILABLE:
        return _zero_features()

    soup = BeautifulSoup(html, "html.parser")

    # Clean hostname for comparison (strip www.)
    domain = hostname.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    # ------------------------------------------------------------------ #
    # Collect link sets                                                    #
    # ------------------------------------------------------------------ #
    href_int, href_ext, href_null = [], [], []
    anchor_safe, anchor_unsafe = [], []

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.lower() in _NULL_HREFS or href.startswith("javascript"):
            href_null.append(href)
            anchor_unsafe.append(href)
        elif href.startswith("http") and domain and domain not in href.lower():
            href_ext.append(href)
            anchor_safe.append(href)
        else:
            href_int.append(href)
            if "#" in href or "javascript" in href.lower() or "mailto" in href.lower():
                anchor_unsafe.append(href)
            else:
                anchor_safe.append(href)

    total_href = len(href_int) + len(href_ext) + len(href_null)

    # Link tags (<link href=...>)
    link_int, link_ext = [], []
    for tag in soup.find_all("link", href=True):
        href = tag["href"].strip()
        if href.startswith("http") and domain and domain not in href.lower():
            link_ext.append(href)
        else:
            link_int.append(href)

    total_link = len(link_int) + len(link_ext)

    # Media (img, audio, embed, iframe, video)
    media_int, media_ext = [], []
    for tag in soup.find_all(["img", "audio", "embed", "video"], src=True):
        src = tag["src"].strip()
        if src.startswith("http") and domain and domain not in src.lower():
            media_ext.append(src)
        else:
            media_int.append(src)

    total_media = len(media_int) + len(media_ext)

    # CSS (external <link rel="stylesheet">)
    css_ext = [
        t["href"] for t in soup.find_all("link", rel="stylesheet")
        if t.get("href", "").startswith("http")
        and domain and domain not in t["href"].lower()
    ]

    # Forms
    form_int, form_ext, form_null = [], [], []
    for tag in soup.find_all("form", action=True):
        action = tag["action"].strip()
        if not action or action.lower() in _NULL_HREFS or action == "about:blank":
            form_null.append(action)
        elif action.startswith("http") and domain and domain not in action.lower():
            form_ext.append(action)
        else:
            form_int.append(action)

    # Favicons
    favicon_ext = [
        t["href"] for t in soup.find_all("link", href=True)
        if (
            (isinstance(t.get("rel"), list) and any(r.endswith("icon") for r in t["rel"]))
            or (isinstance(t.get("rel"), str) and t["rel"].endswith("icon"))
        )
        and t["href"].startswith("http")
        and domain and domain not in t["href"].lower()
    ]

    # ------------------------------------------------------------------ #
    # IFrame detection                                                     #
    # ------------------------------------------------------------------ #
    iframes_invisible = [
        t for t in soup.find_all("iframe")
        if t.get("width") in ("0", 0) or t.get("height") in ("0", 0)
        or "display:none" in (t.get("style") or "").replace(" ", "").lower()
        or "visibility:hidden" in (t.get("style") or "").replace(" ", "").lower()
    ]

    # ------------------------------------------------------------------ #
    # JavaScript / inline-behaviour signals                                #
    # ------------------------------------------------------------------ #
    page_text = str(soup)
    page_lower = page_text.lower().replace(" ", "")

    has_onmouseover = 1 if 'onmouseover="window.status=' in page_lower else 0
    has_popup       = 1 if "prompt(" in page_lower else 0
    right_click_off = 1 if bool(re.search(r"event\.button\s*==\s*2", page_text)) else 0

    # Approximated redirections: meta-refresh or JS location assignments
    meta_refresh = soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    js_redirects  = len(re.findall(
        r"(window\.location|location\.href|location\.replace|location\.assign)\s*=",
        page_text, re.IGNORECASE,
    ))
    redirect_to_ext = len([
        m for m in re.findall(
            r"(?:window\.location|location\.href|location\.replace|location\.assign)\s*=\s*['\"]"
            r"(https?://[^'\"]+)['\"]",
            page_text, re.IGNORECASE,
        )
        if domain and domain not in m.lower()
    ])

    # ------------------------------------------------------------------ #
    # Title / copyright identity                                           #
    # ------------------------------------------------------------------ #
    title_tag = soup.find("title")
    title_text = title_tag.get_text(strip=True) if title_tag else ""
    has_empty_title = 1 if not title_text else 0

    domain_not_in_title = 0
    if title_text and domain:
        domain_not_in_title = 0 if domain in title_text.lower() else 1

    domain_not_in_copyright = 0
    try:
        m = re.search(r"[\u00a9\u2122\u00ae]", page_text)
        if m and domain:
            ctx = page_text[max(0, m.start() - 60): m.start() + 60]
            domain_not_in_copyright = 0 if domain in ctx.lower() else 1
    except Exception:
        pass

    # ------------------------------------------------------------------ #
    # Aggregate ratios                                                     #
    # ------------------------------------------------------------------ #
    def _safe_ratio(num: int, den: int) -> float:
        return round(num / den, 4) if den > 0 else 0.0

    # Hyperlink ratios across ALL link types (href + link-tag + media + form)
    total_all = total_href + total_link + total_media + len(form_int) + len(form_ext) + len(form_null)
    int_all = len(href_int) + len(link_int) + len(media_int) + len(form_int)
    ext_all = len(href_ext) + len(link_ext) + len(media_ext) + len(form_ext)
    null_all = len(href_null) + len(form_null)

    # Redirection approximation: proportion of all links that are JS/meta redirects
    total_redirects = len(meta_refresh) + js_redirects
    ratio_int_redirect = _safe_ratio(total_redirects - redirect_to_ext, max(int_all, 1))
    ratio_ext_redirect = _safe_ratio(redirect_to_ext, max(ext_all, 1))

    features = {
        "nb_hyperlinks":               total_href,
        "ratio_internal_hyperlinks":   _safe_ratio(len(href_int), total_href),
        "ratio_external_hyperlinks":   _safe_ratio(len(href_ext), total_href),
        "ratio_null_hyperlinks":       _safe_ratio(len(href_null), total_href),
        "nb_external_css":             len(css_ext),
        "ratio_internal_redirections": ratio_int_redirect,
        "ratio_external_redirections": ratio_ext_redirect,
        # These require following each link (HTTP requests) — not feasible here;
        # always 0 in static analysis mode.  Can be filled by a network-fetching
        # pipeline if needed.
        "ratio_internal_errors":       0.0,
        "ratio_external_errors":       0.0,
        # Form / login
        "has_login_form":              1 if (form_ext or form_null) else 0,
        "has_external_favicon":        1 if favicon_ext else 0,
        "submits_to_email":            1 if any(
            "mailto:" in a or "mail()" in a
            for a in form_int + form_ext
        ) else 0,
        # Media ratios
        "pct_internal_media":          _safe_ratio(len(media_int) * 100, total_media),
        "pct_external_media":          _safe_ratio(len(media_ext) * 100, total_media),
        # Page identity
        "has_empty_title":             has_empty_title,
        "pct_unsafe_anchors":          _safe_ratio(
            len(anchor_unsafe) * 100, len(anchor_safe) + len(anchor_unsafe)
        ),
        "pct_internal_links_in_tags":  _safe_ratio(len(link_int) * 100, total_link),
        # Suspicious patterns
        "has_null_form_handler":       1 if form_null else 0,
        "has_iframe":                  1 if iframes_invisible else 0,
        "has_onmouseover":             has_onmouseover,
        "has_popup_window":            has_popup,
        "right_click_disabled":        right_click_off,
        "domain_not_in_title":         domain_not_in_title,
        "domain_not_in_copyright":     domain_not_in_copyright,
    }

    assert len(features) == 24, f"Content feature count mismatch: expected 24, got {len(features)}"
    return features
