import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

from app.schemas.report import FalsePositiveReport, ReportResponse

router = APIRouter()
logger = logging.getLogger(__name__)

# Persist reports next to the project data directory
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_REPORTS_DIR  = _PROJECT_ROOT / "data" / "reports"
_REPORTS_FILE = _REPORTS_DIR / "false_positives.jsonl"


def _save_report(entry: dict) -> None:
    """Append one JSON record to the false_positives.jsonl file."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_REPORTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@router.post("/reports/false-positive", response_model=ReportResponse)
async def report_false_positive(report: FalsePositiveReport):
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
