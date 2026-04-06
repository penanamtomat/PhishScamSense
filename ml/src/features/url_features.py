"""
Feature engineering for URL analysis.
Extracts lexical and structural features for the MLP/CapsNet branch.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """Extract numerical/lexical features from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url

    features = {
        # Length-based features
        "url_length": len(full_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        # Count-based features
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_underscores": full_url.count("_"),
        "num_slashes": full_url.count("/"),
        "num_query_params": len(parsed.query.split("&")) if parsed.query else 0,
        "num_fragments": 1 if parsed.fragment else 0,
        "num_digits": sum(c.isdigit() for c in full_url),
        "num_special_chars": sum(not c.isalnum() and c not in ".-_/:" for c in full_url),
        # Entropy
        "url_entropy": _shannon_entropy(full_url),
        "hostname_entropy": _shannon_entropy(hostname),
        # Suspicious patterns
        "has_ip_address": _has_ip_address(hostname),
        "has_punycode": hostname.startswith("xn--"),
        "has_port": 1 if parsed.port and parsed.port not in (80, 443) else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_at_symbol": 1 if "@" in full_url else 0,
        "has_double_slash_redirect": 1 if "//" in path else 0,
        # Domain features
        "subdomain_count": len(hostname.split(".")) - 2 if len(hostname.split(".")) > 2 else 0,
        "tld_length": len(hostname.split(".")[-1]) if "." in hostname else 0,
        # Typosquatting indicators
        "consecutive_consonants_max": _max_consecutive_consonants(hostname),
        "vowel_ratio": _vowel_ratio(hostname),
    }

    return features


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _has_ip_address(hostname: str) -> int:
    """Check if hostname is an IP address."""
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return 1 if ip_pattern.match(hostname) else 0


def _max_consecutive_consonants(text: str) -> int:
    """Find maximum consecutive consonants (typosquatting indicator)."""
    vowels = set("aeiouAEIOU")
    max_count = 0
    current = 0
    for char in text:
        if char.isalpha() and char not in vowels:
            current += 1
            max_count = max(max_count, current)
        else:
            current = 0
    return max_count


def _vowel_ratio(text: str) -> float:
    """Calculate ratio of vowels to total alphabetic characters."""
    alpha_chars = [c for c in text if c.isalpha()]
    if not alpha_chars:
        return 0.0
    vowels = set("aeiouAEIOU")
    return sum(1 for c in alpha_chars if c in vowels) / len(alpha_chars)
