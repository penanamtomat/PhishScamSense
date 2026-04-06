import json
from pathlib import Path

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter()

_PROJECT_ROOT = Path(__file__).resolve().parents[4]  # backend/app/api/routes → project root


def _bloom_filter_path() -> Path:
    configured = Path(settings.MODEL_EXPORTS_PATH)
    if configured.is_absolute():
        return configured / "bloom_filter.json"
    candidate = _PROJECT_ROOT / configured / "bloom_filter.json"
    if candidate.exists():
        return candidate
    return Path.cwd() / configured / "bloom_filter.json"


@router.get("/threats/bloom-filter")
async def get_bloom_filter():
    """Return the Bloom Filter data for the browser extension."""
    bloom_path = _bloom_filter_path()
    if bloom_path.exists():
        with open(bloom_path) as f:
            return json.load(f)
    return {
        "filter": [],
        "version": "0.1.0",
        "updated_at": None,
    }
