"""
Tests for ml.src.features.ssrf_guard — SSRF prevention.
"""

import ipaddress

import pytest

from ml.src.features.ssrf_guard import is_private_ip, validate_url


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------

class TestIsPrivateIP:
    """Verify that private/reserved IPs are detected correctly."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "127.0.0.2",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.1",
            "100.64.0.1",
            "0.0.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_private_ips_rejected(self, ip: str) -> None:
        assert is_private_ip(ip) is True, f"{ip} should be private"

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2001:4860:4860::8888",
        ],
    )
    def test_public_ips_allowed(self, ip: str) -> None:
        assert is_private_ip(ip) is False, f"{ip} should be public"

    def test_unparseable_ip_is_unsafe(self) -> None:
        assert is_private_ip("not-an-ip") is True


# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------

class TestValidateUrl:

    def test_valid_https_url(self) -> None:
        """A public HTTPS URL should be returned as-is."""
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_valid_http_url(self) -> None:
        result = validate_url("http://example.com")
        assert result == "http://example.com"

    def test_reject_file_scheme(self) -> None:
        assert validate_url("file:///etc/passwd") is None

    def test_reject_ftp_scheme(self) -> None:
        assert validate_url("ftp://example.com/file") is None

    def test_reject_javascript_scheme(self) -> None:
        assert validate_url("javascript:alert(1)") is None

    def test_reject_data_scheme(self) -> None:
        assert validate_url("data:text/html,<h1>hi</h1>") is None

    def test_reject_gopher_scheme(self) -> None:
        assert validate_url("gopher://example.com") is None

    def test_reject_empty_url(self) -> None:
        assert validate_url("") is None

    def test_reject_url_too_long(self) -> None:
        long_url = "https://example.com/" + "a" * 2048
        assert validate_url(long_url) is None

    def test_reject_no_hostname(self) -> None:
        assert validate_url("https://") is None

    def test_reject_localhost(self) -> None:
        assert validate_url("http://127.0.0.1:8000/health") is None

    def test_reject_private_ip(self) -> None:
        assert validate_url("http://10.0.0.1/internal") is None

    def test_reject_cloud_metadata(self) -> None:
        assert validate_url("http://169.254.169.254/latest/meta-data/") is None

    def test_reject_link_local(self) -> None:
        assert validate_url("http://169.254.0.1/") is None

    def test_reject_ipv6_loopback(self) -> None:
        assert validate_url("http://[::1]/") is None
