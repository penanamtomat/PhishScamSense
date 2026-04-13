"""
API key authentication for PhishScamSense backend.

When settings.API_KEYS is empty, all requests are allowed (backward compat
during rollout).  Once API keys are configured, every protected endpoint
requires a valid key in the X-API-Key header.
"""

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app.core.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Required authentication dependency.

    Returns the API key string if valid.
    When settings.API_KEYS is empty, returns "anonymous" (auth disabled).
    """
    # No keys configured — auth is disabled (backward compat)
    if not settings.API_KEYS:
        return "anonymous"

    if api_key is None:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    if api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")

    return api_key


async def get_api_key_optional(api_key: str = Security(api_key_header)) -> str | None:
    """
    Optional authentication — used for endpoints that should remain
    accessible without auth (e.g. /health) but still validate keys if present.
    """
    if api_key is None:
        return None
    if settings.API_KEYS and api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key
