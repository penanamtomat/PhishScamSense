import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import predict, reports, threats
from app.core.config import settings
from app.services.ml_predictor import get_predictor

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
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    # Allow all browser extension origins (chrome-extension://, moz-extension://)
    allow_origin_regex=r"(chrome-extension|moz-extension)://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(predict.router, prefix="/api/v1", tags=["prediction"])
app.include_router(threats.router, prefix="/api/v1", tags=["threats"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": get_predictor() is not None}
