import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Request

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import get_api_key
from app.schemas.report import FalsePositiveReport, ReportResponse

router = APIRouter()
logger = logging.getLogger(__name__)

# Persist reports inside /app/data/reports (works in both Docker and local dev)
_REPORTS_DIR  = Path(__file__).resolve().parents[3] / "data" / "reports"
_REPORTS_FILE = _REPORTS_DIR / "false_positives.jsonl"


def _save_report(entry: dict) -> None:
    """Append one JSON record to the false_positives.jsonl file."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_REPORTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@router.post("/reports/false-positive", response_model=ReportResponse)
@limiter.limit(settings.RATE_LIMIT_REPORTS)
async def report_false_positive(
    request: Request,
    report: FalsePositiveReport,
    api_key: str = Depends(get_api_key),
):
    """Accept a false positive report and persist it to data/reports/false_positives.jsonl."""
    report_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    entry = {
        "id":         report_id,
        "url":        report.url,
        "comments":   report.comments,
        "reported_at": timestamp,
        "status":     "pending_review",
    }

    _save_report(entry)

    logger.info("False positive saved | id=%s url=%s file=%s", report_id, report.url, _REPORTS_FILE)

    return ReportResponse(
        id=report_id,
        status="received",
        message="Report saved. We will review this URL and update our detection.",
    )
