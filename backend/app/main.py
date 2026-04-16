import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import predict, reports, threats
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.rate_limit import limiter
from app.core.request_logger import RequestLoggerMiddleware
from app.core.security import get_api_key_optional
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.telemetry import telemetry
from app.services.ml_predictor import get_predictor

setup_logging()
logger = logging.getLogger(__name__)

# Resolve exports path relative to this file's location so it works
# regardless of where uvicorn is started from.
# backend/app/main.py  → parents[1] = backend/  → parents[2] = project root
_HERE = Path(__file__).resolve().parent          # backend/app/
_BACKEND_ROOT = _HERE.parent                     # backend/
_PROJECT_ROOT = _BACKEND_ROOT.parent             # PhishScamSense/


def _resolve_exports_dir() -> Path:
    """Return the absolute path to ml/exports/, tolerating relative config."""
    configured = Path(settings.MODEL_EXPORTS_PATH)
    if configured.is_absolute():
        return configured
    # Try relative to project root first, then CWD as fallback
    candidate = _PROJECT_ROOT / configured
    if candidate.exists():
        return candidate
    return Path.cwd() / configured


@asynccontextmanager
async def lifespan(_app: FastAPI):
    exports_dir = _resolve_exports_dir()
    if exports_dir.exists():
        try:
            get_predictor(exports_dir)
            logger.info("ML models loaded from %s", exports_dir)
        except Exception as exc:
            logger.warning("Could not load ML models from %s: %s", exports_dir, exc)
    else:
        logger.warning(
            "MODEL_EXPORTS_PATH '%s' (resolved: %s) does not exist — predictions disabled",
            settings.MODEL_EXPORTS_PATH,
            exports_dir,
        )
    yield


app = FastAPI(
    title="PhishScamSense API",
    description="Real-Time Multimodal Phishing Defense Backend",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if settings.DOCS_ENABLED else None,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Request/response logging (innermost — runs closest to route handler)
app.add_middleware(RequestLoggerMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"(chrome-extension|moz-extension)://.*" if settings.CORS_ALLOW_EXTENSION_ORIGINS else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
) 

app.include_router(predict.router, prefix="/api/v1", tags=["prediction"])
app.include_router(threats.router, prefix="/api/v1", tags=["threats"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])


@app.get("/health")
async def health_check(api_key: str | None = Depends(get_api_key_optional)):
    """Health check endpoint."""
    status = "healthy" if get_predictor() is not None else "degraded"
    telemetry.log_health_check("/health", status)
    return {"status": status, "model_loaded": get_predictor() is not None}


@app.get("/api/v1/beta_info")
async def beta_info():
    """
    Beta mode information endpoint.

    Returns information about the current beta configuration,
    including the public beta key that users should use.
    """
    if not settings.BETA_MODE:
        return {"beta_mode": False, "message": "This is a production instance."}

    return {
        "beta_mode": True,
        "version": "0.2.0-beta.2",
        "public_beta_key": settings.API_KEYS[0] if settings.API_KEYS else None,
        "telemetry_enabled": settings.ENABLE_TELEMETRY,
        "telemetry_sample_rate": settings.TELEMETRY_SAMPLE_RATE,
        "rate_limiting": "per_ip" if settings.BETA_MODE else "per_api_key",
        "rate_limits": {
            "predict": settings.RATE_LIMIT_PREDICT,
            "reports": settings.RATE_LIMIT_REPORTS,
            "threats": settings.RATE_LIMIT_THREATS,
        },
        "docs_url": "/docs" if settings.DOCS_ENABLED else None,
        "extension_download": "https://phishscam.my.id/extension",
    }
