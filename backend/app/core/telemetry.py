"""
Telemetry module for PhishScamSense beta mode.

Tracks usage patterns WITHOUT collecting PII (personally identifiable information).
This helps improve the ML model and service quality during beta testing.

What we track:
- Request counts (per day, per endpoint)
- Phishing detection results
- Geographic distribution (country level only)
- Extension version distribution
- Top detected threat types

What we DON'T track:
- IP addresses (only hash for deduplication)
- Full URLs (only domain + TLD)
- User identifiers
- Timestamps with precision (only date + hour)
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


class TelemetryEvent:
    """A telemetry event without PII."""

    def __init__(
        self,
        event_type: str,
        data: dict[str, Any],
        sample_rate: float = settings.TELEMETRY_SAMPLE_RATE,
    ):
        """
        Initialize a telemetry event.

        Args:
            event_type: Type of event (e.g., "prediction", "phishing_detected")
            data: Event data (will be sanitized to remove PII)
            sample_rate: Sampling rate (0.0 to 1.0)
        """
        self.event_type = event_type
        self.data = self._sanitize(data)
        self.sample_rate = sample_rate
        self.timestamp = datetime.now(timezone.utc)

    def _sanitize(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Remove PII from event data.

        - URLs: only keep domain + TLD
        - IPs: hash them
        - User agents: only keep browser name + version
        """
        sanitized = {}

        for key, value in data.items():
            if key == "url" and isinstance(value, str):
                # Extract domain + TLD only
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(value)
                    domain_parts = parsed.netloc.split(".")
                    if len(domain_parts) >= 2:
                        # Keep only domain.tld (e.g., "example.com")
                        sanitized["domain"] = ".".join(domain_parts[-2:])
                    else:
                        sanitized["domain"] = "unknown"
                except Exception:
                    sanitized["domain"] = "unknown"

            elif key == "ip" and isinstance(value, str):
                # Hash IP for deduplication without storing actual IP
                sanitized["ip_hash"] = hashlib.sha256(value.encode()).hexdigest()[:16]

            elif key == "user_agent" and isinstance(value, str):
                # Extract browser name only
                ua = value.lower()
                if "chrome" in ua:
                    sanitized["browser"] = "chrome"
                elif "firefox" in ua:
                    sanitized["browser"] = "firefox"
                elif "edg" in ua:
                    sanitized["browser"] = "edge"
                elif "safari" in ua:
                    sanitized["browser"] = "safari"
                else:
                    sanitized["browser"] = "unknown"

            else:
                sanitized[key] = value

        return sanitized

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary for logging."""
        return {
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
        }

    def should_log(self) -> bool:
        """Determine if this event should be logged based on sample rate."""
        import random

        return random.random() < self.sample_rate


class TelemetryLogger:
    """Centralized telemetry logger for beta mode."""

    def __init__(self):
        self.enabled = settings.ENABLE_TELEMETRY and settings.BETA_MODE
        if self.enabled:
            logger.info("Telemetry enabled for beta mode (sample rate: %.1f%%)", settings.TELEMETRY_SAMPLE_RATE * 100)

    def log_prediction(
        self,
        url: str,
        is_phishing: bool,
        confidence: float,
        threat_type: str | None = None,
        phase: int | None = None,
        user_agent: str | None = None,
    ):
        """
        Log a prediction event.

        Args:
            url: The URL that was checked (will be sanitized to domain only)
            is_phishing: Whether the URL was classified as phishing
            confidence: Model confidence score (0.0 to 1.0)
            threat_type: Type of threat if phishing (e.g., "brand_spoofing")
            phase: Detection phase (1=URL-only, 2=content-based)
            user_agent: User agent string (will be sanitized to browser name)
        """
        if not self.enabled:
            return

        event = TelemetryEvent(
            event_type="prediction",
            data={
                "url": url,  # Will be sanitized to domain
                "is_phishing": is_phishing,
                "confidence": round(confidence, 3),
                "threat_type": threat_type,
                "phase": phase,
                "user_agent": user_agent,  # Will be sanitized to browser
            },
        )

        if event.should_log():
            logger.info("[TELEMETRY] %s", json.dumps(event.to_dict()))

    def log_error(
        self,
        error_type: str,
        message: str,
        user_agent: str | None = None,
    ):
        """
        Log an error event.

        Args:
            error_type: Type of error (e.g., "rate_limit_exceeded")
            message: Error message (without sensitive data)
            user_agent: User agent string (will be sanitized)
        """
        if not self.enabled:
            return

        event = TelemetryEvent(
            event_type="error",
            data={
                "error_type": error_type,
                "message": message,
                "user_agent": user_agent,  # Will be sanitized
            },
        )

        # Always log errors (no sampling)
        logger.info("[TELEMETRY] %s", json.dumps(event.to_dict()))

    def log_health_check(self, endpoint: str, status: str):
        """
        Log a health check event (for monitoring uptime).

        Args:
            endpoint: Endpoint being checked
            status: Status (e.g., "healthy", "degraded")
        """
        if not self.enabled:
            return

        # Sample health checks aggressively (only 1%)
        event = TelemetryEvent(
            event_type="health_check",
            data={
                "endpoint": endpoint,
                "status": status,
            },
            sample_rate=0.01,
        )

        if event.should_log():
            logger.info("[TELEMETRY] %s", json.dumps(event.to_dict()))


# Global telemetry logger instance
telemetry = TelemetryLogger()
