import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import predict, reports, threats
from app.core.config import settings
from app.services.ml_predictor import get_predictor

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    exports_dir = Path(settings.MODEL_EXPORTS_PATH)
    if exports_dir.exists():
        try:
            get_predictor(exports_dir)
        except Exception as exc:
            logger.warning("Could not load ML models: %s", exc)
    else:
        logger.warning("MODEL_EXPORTS_PATH %s does not exist — predictions disabled", exports_dir)
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
