import uuid

from fastapi import APIRouter

from app.schemas.report import FalsePositiveReport, ReportResponse
from app.workers.tasks import investigate_false_positive

router = APIRouter()


@router.post("/reports/false-positive", response_model=ReportResponse)
async def report_false_positive(report: FalsePositiveReport):
    """Accept a false positive report and queue investigation."""
    report_id = str(uuid.uuid4())

    # Dispatch async investigation via Celery
    investigate_false_positive.delay(report_id, report.url)

    return ReportResponse(
        id=report_id,
        status="queued",
        message="Report received. Investigation will be processed.",
    )
