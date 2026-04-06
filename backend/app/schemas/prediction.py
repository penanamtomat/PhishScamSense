from pydantic import BaseModel


class PredictionRequest(BaseModel):
    url: str


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    features: dict | None = None
