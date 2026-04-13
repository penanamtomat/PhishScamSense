import html

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 2048
MAX_COMMENTS_LENGTH = 2000


class FalsePositiveReport(BaseModel):
    url: str = Field(..., max_length=MAX_URL_LENGTH)
    comments: str | None = Field(default=None, max_length=MAX_COMMENTS_LENGTH)

    @field_validator("url")
    @classmethod
    def validate_and_sanitize_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # HTML-escape to prevent stored XSS when written to JSONL
        v = html.escape(v, quote=True)
        return v

    @field_validator("comments")
    @classmethod
    def sanitize_comments(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        # HTML-escape to prevent stored XSS
        v = html.escape(v, quote=True)
        return v


class ReportResponse(BaseModel):
    id: str
    status: str
    message: str
