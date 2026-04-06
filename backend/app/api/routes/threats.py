import json
from pathlib import Path

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter()


@router.get("/threats/bloom-filter")
async def get_bloom_filter():
    """Return the Bloom Filter data for the browser extension."""
    bloom_path = Path(settings.MODEL_EXPORTS_PATH) / "bloom_filter.json"
    if bloom_path.exists():
        with open(bloom_path) as f:
            return json.load(f)
    return {
        "filter": [],
        "version": "0.1.0",
        "updated_at": None,
    }
