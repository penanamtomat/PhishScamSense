from fastapi import APIRouter, HTTPException

from app.core.config import settings
from app.schemas.prediction import PredictionRequest, PredictionResponse
from app.services.ml_predictor import get_predictor

router = APIRouter()


@router.post("/predict", response_model=PredictionResponse)
async def predict_url(request: PredictionRequest):
    """Predict whether a URL is benign, phishing, malware, or spam."""
    predictor = get_predictor()
    if predictor is None:
        raise HTTPException(status_code=503, detail="ML model not loaded")

    try:
        result = predictor.predict(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

    return PredictionResponse(
        phishing=result["phishing"],
        confidence=result["confidence"],
        label=result["label"],
        threat_type=result["threat_type"],
        features=result.get("features"),
    )
