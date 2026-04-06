from fastapi import APIRouter

router = APIRouter()


@router.get("/threats/bloom-filter")
async def get_bloom_filter():
    """Return the current Bloom Filter data for the browser extension."""
    # TODO: Load actual bloom filter from database/cache
    return {
        "filter": [],
        "version": "0.1.0",
        "updated_at": None,
    }
