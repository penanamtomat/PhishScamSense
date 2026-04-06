import httpx
from fastapi import APIRouter, HTTPException

from app.core.config import settings
from app.schemas.prediction import PredictionRequest, PredictionResponse

router = APIRouter()


@router.post("/predict", response_model=PredictionResponse)
async def predict_url(request: PredictionRequest):
    """Send URL to ML inference service for phishing prediction."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{settings.MODEL_SERVICE_URL}/predict",
                json={"url": request.url},
            )
            response.raise_for_status()
            result = response.json()

        return PredictionResponse(
            phishing=result["phishing"],
            confidence=result["confidence"],
            features=result.get("features"),
        )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"ML service unavailable: {e}")
