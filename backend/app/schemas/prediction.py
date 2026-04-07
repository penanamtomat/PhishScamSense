from pydantic import BaseModel


class PredictionRequest(BaseModel):
    url: str
    html: str | None = None  # optional page HTML from browser extension


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    label: int = 0
    threat_type: str = "benign"
    features: dict | None = None
