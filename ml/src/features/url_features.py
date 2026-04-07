"""
URL-only feature extraction — 57 features.

Design decisions
----------------
1.  Path features computed from full URL, trained with augmented benign data.
    To eliminate training/inference distribution mismatch the benign training
    set is augmented with synthetic paths (data_loader.py adds common path
    suffixes to each bare domain).  At inference time the full URL is used.
    This allows the model to learn that paths are not inherently phishing signals
    while still detecting suspicious path patterns (phish-hint words, embedded
    HTTP tokens, double-slash redirects).

2.  Public suffix list via tldextract.
    Naive dot-splitting misclassifies country-SLD domains like sso.ui.ac.id:
    "ac" would be treated as the registrable domain, triggering false signals.
    tldextract uses the Mozilla Public Suffix List to correctly identify:
      sso.ui.ac.id  → subdomain=sso, domain=ui, suffix=ac.id
    If tldextract is unavailable it falls back to naive two-label splitting.

3.  www. normalisation.
    www. is stripped before computing structural features to avoid false
    consonant-run (www = 3 consonants) and subdomain-count signals.

Feature groups (57 total)
--------------------------
A  Character counts in full URL          (15)
B  Path-level features                   ( 6)
C  Hostname-level numeric                (10)
D  Structural / suspicious-pattern flags (12)
E  Linguistic / entropy                  ( 4)
F  Word-based                            ( 5)
G  Domain-identity / brand               ( 5)
                                         ---
                                          57
"""

import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Optional dependency: tldextract
# ---------------------------------------------------------------------------
try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Static data
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_BRANDS_FILE = _HERE.parents[2] / "scripts" / "allbrands.txt"
_BRANDS: list[str] = []
_BRANDS_SET: frozenset = frozenset()
_BRANDS_BY_LEN: dict[int, list[str]] = {}
try:
    with open(_BRANDS_FILE, encoding="utf-8", errors="ignore") as _f:
        _BRANDS = [ln.strip().lower() for ln in _f if ln.strip()]
    _BRANDS_SET = frozenset(_BRANDS)
    for _b in _BRANDS:
        _BRANDS_BY_LEN.setdefault(len(_b), []).append(_b)
except FileNotFoundError:
    pass

SHORTENING_RE = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl"
    r"|tr\.im|is\.gd|cli\.gs|ff\.im|tiny\.cc|url4\.eu|su\.pr|snipurl\.com"
    r"|short\.to|budurl\.com|ping\.fm|post\.ly|bkite\.com|snipr\.com"
    r"|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com"
    r"|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com"
    r"|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|u\.to|j\.mp|buzurl\.com"
    r"|cutt\.us|yourls\.org|v\.gd|link\.zip\.net|rb\.gy|t\.ly"
    r"|shorturl\.at|urlzs\.com|clck\.ru|mcaf\.ee",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = frozenset({
    "fit", "tk", "gp", "ga", "work", "ml", "date", "wang", "men", "icu",
    "online", "click", "country", "stream", "download", "xin", "racing",
    "jetzt", "ren", "mom", "party", "review", "trade", "accountants",
    "science", "ninja", "xyz", "faith", "zip", "cricket", "win",
    "accountant", "realtor", "top", "christmas", "gdn", "link",
    "club", "exposed", "audio", "website", "pw", "cf", "info",
})

PHISH_HINTS = frozenset({
    "wp", "login", "includes", "admin", "content", "site", "images", "js",
    "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "signin",
    "view", "secure", "banking", "confirm", "update", "verify", "account",
    "webscr", "validate", "checkout", "payment", "password", "passwd",
    "credential", "wallet", "invoice", "support", "helpdesk", "recover",
    "unlock", "suspend",
})

SUSPICIOUS_DOMAIN_RE = re.compile(
    r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es"
    r"|sweddy\.com|myjino\.ru|96\.lt",
    re.IGNORECASE,
)

_VOWELS = frozenset("aeiouAEIOU")


# ---------------------------------------------------------------------------
# Domain parsing helpers
# ---------------------------------------------------------------------------

def _parse_domain(hostname: str) -> tuple[str, str, str]:
    """
    Return (subdomain, domain, suffix) for *hostname* using tldextract when
    available, falling back to naive two-label splitting.

    Example:
        sso.ui.ac.id  → ("sso", "ui", "ac.id")
        www.google.com → ("www", "google", "com")
        paypal-secure.info → ("", "paypal-secure", "info")
    """
    if _TLDEXTRACT_AVAILABLE:
        r = _tldextract.extract(hostname)
        return r.subdomain, r.domain, r.suffix
    # Fallback: naive two-label split
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    return "", hostname, ""


# ---------------------------------------------------------------------------
# Feature helper functions
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_ip(hostname: str) -> int:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return 1
    if re.match(r"^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$", hostname):
        return 1
    return 0


def _max_consecutive_consonants(text: str) -> int:
    max_c = cur = 0
    for ch in text:
        if ch.isalpha() and ch not in _VOWELS:
            cur += 1
            max_c = max(max_c, cur)
        else:
            cur = 0
    return max_c


def _vowel_ratio(text: str) -> float:
    alpha = [c for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c in _VOWELS) / len(alpha)


def _char_repeat_count(words: list[str]) -> int:
    """Count runs of 2–5 identical consecutive characters."""
    total = 0
    for word in words:
        for run in (2, 3, 4, 5):
            for i in range(len(word) - run + 1):
                if len(set(word[i : i + run])) == 1:
                    total += 1
    return total


def _split_words(text: str) -> list[str]:
    return [w for w in re.split(r"[\W_]+", text) if w]


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _min_brand_distance(domain: str) -> int:
    """Min Levenshtein distance to any brand (±3 char length window)."""
    if not _BRANDS_BY_LEN or not domain:
        return 999
    domain = domain.lower()
    dom_len = len(domain)
    # Only compare against brands within ±3 chars in length (pre-grouped at load)
    candidates: list[str] = []
    for dl in range(max(1, dom_len - 3), dom_len + 4):
        candidates.extend(_BRANDS_BY_LEN.get(dl, []))
    if not candidates:
        return 999
    return min(_levenshtein(domain, b) for b in candidates)


def _brand_in_subdomain(subdomain: str, domain: str) -> int:
    if not subdomain or not _BRANDS_SET:
        return 0
    sub_lower = subdomain.lower()
    dom_lower = domain.lower()
    for brand in _BRANDS_SET:
        if brand in sub_lower and brand not in dom_lower:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_url_features(url: str) -> dict:
    """
    Extract 57 URL-only features from *url*.

    The URL is normalised to scheme+hostname only before feature extraction
    so that path/query features are always 0 — eliminating the training-data
    bias where benign=bare domain and phishing=full URL with path/query.
    """
    if not url.startswith(("http://", "https://", "ftp://")):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = (parsed.hostname or "").lower()
    scheme   = parsed.scheme

    # --- Hostname normalisation ---
    # Strip www. for structural analysis (avoid false consonant-run / subdomain signals)
    effective_hostname = hostname[4:] if hostname.startswith("www.") else hostname

    # Path for Group B features.
    path = parsed.path or ""

    # Hostname-only URL for character-count features (Groups A, C, D).
    host_url = f"{scheme}://{effective_hostname}"

    # Domain parts via Public Suffix List
    subdomain, domain_label, suffix = _parse_domain(effective_hostname)
    tld = suffix.split(".")[-1] if suffix else ""  # rightmost label of suffix

    # Registrable domain label (not the full suffix, just the meaningful label)
    registrable = domain_label  # e.g. "google", "paypal-update-secure", "ui"

    # Words from hostname
    host_words = _split_words(effective_hostname)

    # ------------------------------------------------------------------ #
    # Group A — Character counts in full URL                   (15)       #
    # Counted across the entire URL string.  Query-specific counts         #
    # (count_and, count_equal, count_question) use the query component     #
    # only to avoid double-counting from the path.                         #
    # ------------------------------------------------------------------ #
    # NOTE: url_length and count_* are hostname-scoped, NOT full-URL-scoped.
    # Query string character counts (count_and, count_equal, count_question) are
    # always 0 — they create an irreducible training/inference bias: benign training
    # data is bare domains (count=0) while real browser URLs have query strings
    # (count>0), so the model incorrectly learns "query params = phishing".
    # Path analysis in Group B captures suspicious path-level signals instead.
    a = {
        "url_length":       len(effective_hostname),   # hostname length only
        "count_at":         host_url.count("@"),
        "count_comma":      host_url.count(","),
        "count_dollar":     host_url.count("$"),
        "count_semicolumn": host_url.count(";"),
        "count_space":      host_url.count(" ") + host_url.count("%20"),
        "count_and":        0,   # zeroed — query bias (see NOTE above)
        "count_equal":      0,   # zeroed — query bias
        "count_percentage": host_url.count("%"),
        "count_question":   0,   # zeroed — query bias
        "count_colon":      host_url.count(":"),
        "count_star":       host_url.count("*"),
        "count_or":         host_url.count("|"),
        "count_tilde":      host_url.count("~"),
        "count_http_token": 1 if re.search(r"https?://", path, re.IGNORECASE) else 0,
    }

    # ------------------------------------------------------------------ #
    # Group B — Path-level features                             ( 6)       #
    # Computed from the full URL path.  Benign training data is augmented   #
    # with synthetic paths (data_loader.py) so the model learns that        #
    # path features alone do not imply phishing.                            #
    # ------------------------------------------------------------------ #
    path_lower = path.lower()
    b = {
        "path_length":               len(path),
        "num_slashes":               path.count("/"),
        "phish_hints_count":         sum(1 for h in PHISH_HINTS if h in path_lower),
        "brand_in_path":             1 if _BRANDS_SET and any(
                                         br in path_lower for br in _BRANDS_SET
                                     ) else 0,
        "has_path_extension":        1 if re.search(r"\.\w{2,5}(?:[?#]|$)", path) else 0,
        "has_double_slash_redirect": 1 if "//" in path else 0,
    }

    # ------------------------------------------------------------------ #
    # Group C — Hostname-level numeric                          (10)       #
    # NOTE: use effective_hostname (www. stripped) for ALL hostname        #
    # metrics so that www.google.com and google.com produce identical      #
    # features.                                                            #
    # ------------------------------------------------------------------ #
    num_dig_host = sum(c.isdigit() for c in effective_hostname)
    num_dig_url  = num_dig_host  # same as above (hostname-only)
    # Subtract dots that belong to the suffix (country SLD).
    # e.g. sso.ui.ac.id: total_dots=3, suffix_dots(ac.id)=1 → adjusted=2
    # This prevents .ac.id, .co.uk, etc. from looking more suspicious than .com
    suffix_dots = suffix.count(".")
    c = {
        "hostname_length":    len(effective_hostname),    # www. already stripped
        "num_dots":           max(0, effective_hostname.count(".") - suffix_dots),
        "num_hyphens":        effective_hostname.count("-"),
        "num_underscores":    effective_hostname.count("_"),
        "num_digits_host":    num_dig_host,
        "ratio_digits_host":  num_dig_host / max(len(effective_hostname), 1),
        "num_digits_url":     num_dig_url,
        "ratio_digits_url":   num_dig_url / max(len(host_url), 1),
        "url_entropy":        _shannon_entropy(effective_hostname),
        "hostname_entropy":   _shannon_entropy(effective_hostname),  # same field, kept for compat
    }

    # ------------------------------------------------------------------ #
    # Group D — Structural / suspicious-pattern flags           (12)       #
    # ------------------------------------------------------------------ #
    d = {
        "has_ip_address":         _has_ip(hostname),
        "has_punycode":           1 if hostname.startswith("xn--") else 0,
        "has_port":               1 if parsed.port and parsed.port not in (80, 443) else 0,
        "has_https":              1 if scheme == "https" else 0,
        "has_at_symbol":          1 if "@" in host_url else 0,
        "is_shortening_service":  1 if SHORTENING_RE.search(hostname) else 0,
        # Hyphen inside the registrable domain label (paypal-verify, secure-login)
        "has_prefix_suffix":      1 if "-" in registrable else 0,
        "has_tld_in_path":        1 if tld and ("." + tld) in path_lower else 0,
        "has_tld_in_subdomain":   1 if tld and tld in subdomain.lower() else 0,
        "has_abnormal_subdomain": 1 if re.search(
            r"(https?://(w[w]?|\d))([w]?(\d|-))", host_url
        ) else 0,
        "has_suspicious_tld":     1 if tld in SUSPICIOUS_TLDS else 0,
        "char_repeat_count":      _char_repeat_count(host_words),
    }

    # ------------------------------------------------------------------ #
    # Group E — Linguistic / entropy                            ( 4)       #
    # ------------------------------------------------------------------ #
    e = {
        "consecutive_consonants_max": _max_consecutive_consonants(effective_hostname),
        "vowel_ratio":                _vowel_ratio(effective_hostname),
        "num_special_chars":          sum(
            not c.isalnum() and c not in ".-_" for c in effective_hostname
        ),
        "has_statistical_report":     1 if SUSPICIOUS_DOMAIN_RE.search(host_url) else 0,
    }

    # ------------------------------------------------------------------ #
    # Group F — Word-based                                      ( 5)       #
    # ------------------------------------------------------------------ #
    f_ = {
        "num_words":       len(host_words),
        "avg_word_length": sum(len(w) for w in host_words) / max(len(host_words), 1),
        "max_word_length": max((len(w) for w in host_words), default=0),
        "min_word_length": min((len(w) for w in host_words), default=0),
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
    }

    # ------------------------------------------------------------------ #
    # Group G — Domain identity / brand / typosquatting         ( 5)       #
    # ------------------------------------------------------------------ #
    min_dist = _min_brand_distance(registrable)
    g = {
        "tld_length":              len(tld),      # rightmost TLD label only (e.g. "id", "com")
        "domain_in_brand_exact":   1 if registrable.lower() in _BRANDS_SET else 0,
        "typosquatting_min_dist":  min_dist if min_dist < 999 else 999,
        "typosquatting_suspicious":1 if 0 < min_dist <= 2 else 0,
        "brand_in_subdomain":      _brand_in_subdomain(subdomain, registrable),
    }

    features = {**a, **b, **c, **d, **e, **f_, **g}
    assert len(features) == 57, (
        f"URL feature count mismatch: expected 57, got {len(features)}"
    )
    return features
