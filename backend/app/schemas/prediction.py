from pydantic import BaseModel


class PredictionRequest(BaseModel):
    url: str


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    label: int = 0
    threat_type: str = "benign"
    features: dict | None = None
