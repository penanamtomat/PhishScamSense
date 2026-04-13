"""
Rate limiting configuration using slowapi.

Rate limits are applied per API key (when present) or per IP address.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address


def _get_identifier(request) -> str:
    """Rate limit per API key if present, otherwise per IP."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"key:{api_key}"
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=_get_identifier, default_limits=["60/minute"])
