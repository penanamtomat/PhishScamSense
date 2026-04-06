from pydantic import BaseModel


class FalsePositiveReport(BaseModel):
    url: str
    comments: str | None = None


class ReportResponse(BaseModel):
    id: str
    status: str
    message: str
