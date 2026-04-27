import re

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 2048

# URL format: must start with http:// or https:// and have a valid hostname
_URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}"
    r"(?::\d{1,5})?"
    r"(?:/[^\s]*)?$"
)


class PredictionRequest(BaseModel):
    url: str = Field(..., max_length=MAX_URL_LENGTH)
    html: str | None = Field(default=None, max_length=1_000_000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH}")
        if not _URL_PATTERN.match(v):
            raise ValueError(
                "URL must start with http:// or https:// and have a valid hostname"
            )
        # Block dangerous schemes
        lower = v.lower()
        if "javascript:" in lower or "data:" in lower:
            raise ValueError("URL scheme not allowed")
        return v


class ShortenerAnalysis(BaseModel):
    detected: bool
    final_url: str
    hop_count: int
    html_fetched: bool


class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    label: int = 0
    threat_type: str = "benign"
    features: dict | None = None
    shortener_analysis: ShortenerAnalysis | None = None
