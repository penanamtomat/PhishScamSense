from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    url: str
    html: str | None = Field(default=None, max_length=1_000_000)


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    label: int = 0
    threat_type: str = "benign"
    features: dict | None = None
