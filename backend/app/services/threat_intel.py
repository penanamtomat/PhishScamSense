import httpx

from app.core.config import settings


class ThreatIntelService:
    """Service for querying third-party threat intelligence APIs."""

    async def check_virustotal(self, url: str) -> dict:
        """Query VirusTotal API v3 for URL analysis."""
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured"}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                data={"url": url},
            )
            response.raise_for_status()
            return response.json()

    async def check_google_safe_browsing(self, url: str) -> dict:
        """Query Google Safe Browsing API v4."""
        if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
            return {"error": "Google Safe Browsing API key not configured"}

        payload = {
            "client": {"clientId": "phishsense", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            response.raise_for_status()
            return response.json()


threat_intel_service = ThreatIntelService()
