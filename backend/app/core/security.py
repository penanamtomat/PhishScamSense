"""
API key authentication for PhishScamSense backend.

Beta mode: single public key for all beta users with enhanced monitoring.
Production mode: per-user API keys with full authentication.

When settings.API_KEYS is empty, all requests are allowed (backward compat
during rollout).  Once API keys are configured, every protected endpoint
requires a valid key in the X-API-Key header.
"""

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader

from app.core.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _is_beta_mode() -> bool:
    """Check if we're running in beta mode."""
    return settings.BETA_MODE and len(settings.API_KEYS) == 1


def _is_valid_user_agent(user_agent: str | None) -> bool:
    """
    Validate user agent in beta mode to prevent abuse.

    In beta mode, we allow requests from browser extensions.
    Empty list = allow all user agents.
    """
    if not settings.ALLOWED_USER_AGENTS:
        return True

    if not user_agent:
        return False

    # Check if user agent starts with any allowed prefix
    return any(user_agent.startswith(allowed) for allowed in settings.ALLOWED_USER_AGENTS)


async def get_api_key(
    request: Request,
    api_key: str = Security(api_key_header)
) -> str:
    """
    Required authentication dependency.

    Beta mode: validates the public beta key + optional user agent check.
    Production mode: validates per-user API keys.
    When settings.API_KEYS is empty, returns "anonymous" (auth disabled).

    Args:
        request: FastAPI request object for UA validation
        api_key: API key from X-API-Key header

    Returns:
        The validated API key string

    Raises:
        HTTPException: If authentication fails
    """
    # No keys configured — auth is disabled (backward compat)
    if not settings.API_KEYS:
        return "anonymous"

    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header. Get your beta key at https://phishscam.my.id"
        )

    if api_key not in settings.API_KEYS:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key. Get your beta key at https://phishscam.my.id"
        )

    # Beta mode: additional user agent validation to prevent abuse
    if _is_beta_mode():
        user_agent = request.headers.get("User-Agent")
        if not _is_valid_user_agent(user_agent):
            raise HTTPException(
                status_code=403,
                detail="Invalid user agent. Please use the official browser extension."
            )

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
