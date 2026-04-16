"""
Rate limiting configuration using slowapi.

Beta mode: Rate limits are applied per IP address (since all beta users share the same key).
Production mode: Rate limits are applied per API key.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def _get_identifier(request) -> str:
    """
    Rate limit identifier based on mode.

    Beta mode: Always use IP address (even if API key is present).
    Production mode: Use API key if present, otherwise fall back to IP.

    This prevents abuse in beta mode where all users share the same public key.
    """
    # Beta mode: always rate limit by IP to prevent abuse
    if settings.BETA_MODE:
        return f"ip:{get_remote_address(request)}"

    # Production mode: rate limit by API key if present
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"key:{api_key}"
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=_get_identifier, default_limits=["60/minute"])
