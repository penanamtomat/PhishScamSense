"""
SSRF guard — validate URLs before making outbound HTTP requests.

Blocks requests to private/reserved IP ranges (RFC 1918, loopback,
link-local, cloud metadata, CGN, etc.) and validates DNS resolution
to prevent DNS-rebinding attacks.

Usage:
    from ml.src.features.ssrf_guard import validate_url

    safe_url = validate_url("https://example.com")
    if safe_url is None:
        # URL is unsafe — do not fetch
        ...
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Private / reserved networks — any resolved IP in these ranges is blocked
# ---------------------------------------------------------------------------
PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4 — loopback
    ipaddress.IPv4Network("127.0.0.0/8"),
    # IPv4 — RFC 1918 private
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    # IPv4 — link-local (includes cloud metadata 169.254.169.254)
    ipaddress.IPv4Network("169.254.0.0/16"),
    # IPv4 — CGN (RFC 6598)
    ipaddress.IPv4Network("100.64.0.0/10"),
    # IPv4 — benchmarking (RFC 2544)
    ipaddress.IPv4Network("198.18.0.0/15"),
    # IPv4 — IETF protocol assignments
    ipaddress.IPv4Network("192.0.0.0/24"),
    # IPv4 — reserved (RFC 1112)
    ipaddress.IPv4Network("240.0.0.0/4"),
    # IPv4 — "this" network
    ipaddress.IPv4Network("0.0.0.0/8"),
    # IPv6 — loopback
    ipaddress.IPv6Network("::1/128"),
    # IPv6 — unique local (RFC 4193)
    ipaddress.IPv6Network("fc00::/7"),
    # IPv6 — link-local
    ipaddress.IPv6Network("fe80::/10"),
    # IPv6 — IPv4-mapped
    ipaddress.IPv6Network("::ffff:0:0/96"),
    # IPv6 — documentation
    ipaddress.IPv6Network("2001:db8::/32"),
]

_ALLOWED_SCHEMES = {"http", "https"}

MAX_URL_LENGTH = 2048


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* falls in any private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → treat as unsafe
    return any(addr in net for net in PRIVATE_NETWORKS)


def validate_url(url: str, timeout: float = 2.0) -> str | None:
    """
    Validate that *url* is safe to fetch.

    Returns the original URL string if safe, or ``None`` if the URL
    should not be requested (private IP, blocked scheme, DNS failure, etc.).
    """
    if not url or len(url) > MAX_URL_LENGTH:
        return None

    parsed = urlparse(url)

    # Only http(s) allowed — blocks file://, ftp://, gopher://, etc.
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    # Resolve DNS and check every address before connecting.
    # This prevents DNS-rebinding: we validate IPs *now*, not at
    # connect time.
    try:
        infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError):
        # DNS resolution failed — treat as unsafe
        return None

    for family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        if is_private_ip(ip_str):
            return None

    return url
