from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishScamSense"
    API_V1_PREFIX: str = "/api/v1"

    # Authentication — list of valid API keys (JSON array of strings).
    # When empty, auth is disabled (backward compat).
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    API_KEYS: list[str] = []

    # Swagger UI — set to False in production to disable /docs and /openapi.json
    DOCS_ENABLED: bool = True

    # CORS — explicit list of allowed origins (no wildcard).
    # Browser extension origins are handled via CORS_ALLOW_EXTENSION_ORIGINS.
    CORS_ORIGINS: list[str] = []

    # Allow chrome-extension:// and moz-extension:// origins
    CORS_ALLOW_EXTENSION_ORIGINS: bool = True

    # Rate limiting (requests per minute per API key / IP)
    RATE_LIMIT_PREDICT: str = "10/second;500/hour"
    RATE_LIMIT_REPORTS: str = "5/minute;50/day"
    RATE_LIMIT_THREATS: str = "20/second;1000/hour"

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
