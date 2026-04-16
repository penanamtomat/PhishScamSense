from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishScamSense"
    API_V1_PREFIX: str = "/api/v1"

    # Authentication — list of valid API keys (JSON array of strings).
    # Beta mode: single public key for all beta users
    # Production: list of per-user keys
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    API_KEYS: list[str] = ["phishscamsense-beta-2024-public"]

    # Beta mode flag - enables enhanced monitoring while keeping service open
    BETA_MODE: bool = True

    # Telemetry (beta mode only) - Log usage patterns without PII
    ENABLE_TELEMETRY: bool = True
    TELEMETRY_SAMPLE_RATE: float = 0.1  # Log 10% of requests for privacy

    # Swagger UI — set to False in production to disable /docs and /openapi.json
    DOCS_ENABLED: bool = True

    # CORS — explicit list of allowed origins (no wildcard).
    # Browser extension origins are handled via CORS_ALLOW_EXTENSION_ORIGINS.
    CORS_ORIGINS: list[str] = []

    # Allow chrome-extension:// and moz-extension:// origins
    CORS_ALLOW_EXTENSION_ORIGINS: bool = True

    # Rate limiting
    # Beta mode: per-IP limits (since all users share the same key)
    # Production: per-API-key limits
    RATE_LIMIT_PREDICT: str = "60/minute;1000/hour"  # Per-IP in beta mode
    RATE_LIMIT_REPORTS: str = "10/minute;100/day"
    RATE_LIMIT_THREATS: str = "100/second;10000/hour"

    # User Agent whitelist (optional, for blocking abuse in beta mode)
    # Empty list = allow all user agents
    ALLOWED_USER_AGENTS: list[str] = [
        "Mozilla/5.0",  # Standard browser UA prefix (extensions)
        "PhishScamSense-Extension",
    ]

    # RabbitMQ
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672//"

    # Celery
    CELERY_BROKER_URL: str = "amqp://guest:guest@localhost:5672//"
    CELERY_RESULT_BACKEND: str = "rpc://"

    # ML Model
    MODEL_SERVICE_URL: str = "http://localhost:3000"
    MODEL_EXPORTS_PATH: str = "ml/exports"

    # Third-party APIs
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""

    # MLflow
    MLFLOW_TRACKING_URI: str = "http://localhost:5000"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
