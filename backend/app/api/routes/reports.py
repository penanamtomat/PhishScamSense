import logging
import uuid

from fastapi import APIRouter

from app.schemas.report import FalsePositiveReport, ReportResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/reports/false-positive", response_model=ReportResponse)
async def report_false_positive(report: FalsePositiveReport):
    """Accept a false positive report and log it for review."""
    report_id = str(uuid.uuid4())

    logger.info(
        "False positive report received | id=%s url=%s comments=%s",
        report_id,
        report.url,
        report.comments,
    )

    return ReportResponse(
        id=report_id,
        status="received",
        message="Report received. Thank you for helping improve our detection.",
    )
