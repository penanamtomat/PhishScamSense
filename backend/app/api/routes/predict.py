import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import get_api_key
from app.schemas.prediction import PredictionRequest, PredictionResponse
from app.services.ml_predictor import get_predictor

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/predict", response_model=PredictionResponse)
@limiter.limit(settings.RATE_LIMIT_PREDICT)
async def predict_url(
    request: Request,
    body: PredictionRequest,
    include_features: bool = False,
    api_key: str = Depends(get_api_key),
):
    """Predict whether a URL is benign, phishing, malware, or spam."""
    req_id = getattr(request.state, "req_id", "?")
    predictor = get_predictor()
    if predictor is None:
        logger.warning("Predict called but model not loaded | req_id=%s", req_id)
        raise HTTPException(status_code=503, detail="ML model not loaded")

    phase = "2" if body.html else "1"
    html_size = len(body.html) if body.html else 0
    logger.debug(
        "Predict start | phase=%s url=%s html_size=%dB | req_id=%s",
        phase, body.url, html_size, req_id,
    )

    try:
        result = predictor.predict(body.url, html=body.html)
    except Exception as exc:
        logger.exception(
            "Prediction failed | phase=%s url=%s html_size=%dB | req_id=%s",
            phase, body.url, html_size, req_id,
        )
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}")

    logger.info(
        "Predict done | phase=%s label=%s confidence=%.4f phishing=%s url=%s | req_id=%s",
        phase, result["threat_type"], result["confidence"], result["phishing"], body.url, req_id,
    )

    return PredictionResponse(
        phishing=result["phishing"],
        confidence=result["confidence"],
        label=result["label"],
        threat_type=result["threat_type"],
        features=result.get("features") if include_features else None,
    )
