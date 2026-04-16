# 🎯 Approach Kontrol Penggunaan User - PhishScamSense

## 📋 Pendahuluan

Dokumentasi ini menjelaskan approach **"Middle Ground"** untuk mengontrol penggunaan user PhishScamSense selama fase beta, yaitu:

✅ **Tetap OPEN & mudah untuk user**  
✅ **Tetap ada kontrol & monitoring**  
✅ **Migration path yang mulus ke account system**

---

## 🎯 Problem Statement

### Situasi Saat Ini (Fully Open)

```python
# backend/app/core/config.py:11
API_KEYS: list[str] = []  # ← KOSONG = Anonymous access

# backend/app/core/security.py:24-26
if not settings.API_KEYS:
    return "anonymous"  # ← AUTH DISABLED!
```

**Masalah:**
- ❌ Tidak bisa tracking penggunaan per user
- ❌ Tidak bisa rate limit per user
- ❌ Tidak bisa blokir user abuse
- ❌ Tidak ada telemetry
- ❌ Tidak bisa monetisasi nanti

---

## 🔐 Solusi: Beta Key Approach

### Konsep

Gunakan **satu API Key publik** untuk semua beta users, tapi dengan **enhanced controls**:

```python
# Alih-alih kosong:
API_KEYS: list[str] = []  # ❌ Fully open

# Gunakan:
API_KEYS: list[str] = ["phishscamsense-beta-2024-public"]  # ✅ Controlled
```

---

## 📐 Implementation Plan

### **STEP 1: Update Configuration**

#### File: `backend/app/core/config.py`

```python
from pydantic_settings import BaseSettings
from typing import Literal

class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishScamSense"
    API_V1_PREFIX: str = "/api/v1"
    
    # Authentication
    # Beta mode: single public key for all beta users
    # Production: list of per-user keys
    API_KEYS: list[str] = [
        "phishscamsense-beta-2024-public"  # Public beta key
    ]
    
    # Beta mode flag
    BETA_MODE: bool = True
    
    # Telemetry (beta mode only)
    ENABLE_TELEMETRY: bool = True  # Log usage patterns (no PII)
    TELEMETRY_SAMPLE_RATE: float = 0.1  # Log 10% of requests
    
    # Swagger UI
    DOCS_ENABLED: bool = True
    
    # CORS - untuk browser extension
    CORS_ORIGINS: list[str] = []
    CORS_ALLOW_EXTENSION_ORIGINS: bool = True
    
    # Rate limiting
    # Beta mode: per-IP limits (since semua pakai key yang sama)
    # Production: per-API-key limits
    RATE_LIMIT_PREDICT: str = "60/minute;1000/hour"  # Per-IP di beta
    RATE_LIMIT_REPORTS: str = "10/minute;100/day"
    RATE_LIMIT_THREATS: str = "100/second;10000/hour"
    
    # User Agent whitelist (optional, untuk block abuse)
    ALLOWED_USER_AGENTS: list[str] = [
        "Mozilla/5.0",  # Browser extension
        "PhishScamSense-Extension",
    ]
    
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
```

---

### **STEP 2: Enhanced Security Module**

#### File: `backend/app/core/security.py` (UPDATE)

```python
"""
API key authentication for PhishScamSense backend.

Beta mode: Single public key for all beta users with enhanced controls.
Production mode: Per-user API keys with full accountability.
"""

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Beta key identifier
BETA_KEY = "phishscamsense-beta-2024-public"


def _is_beta_mode() -> bool:
    """Check if running in beta mode."""
    return settings.BETA_MODE and len(settings.API_KEYS) == 1 and settings.API_KEYS[0] == BETA_KEY


def _is_valid_user_agent(user_agent: str) -> bool:
    """Check if user agent is allowed (optional anti-abuse measure)."""
    if not settings.ALLOWED_USER_AGENTS:
        return True  # No restriction
    
    ua_lower = user_agent.lower()
    for allowed in settings.ALLOWED_USER_AGENTS:
        if allowed.lower() in ua_lower:
            return True
    return False


async def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Required authentication dependency.
    
    Beta mode: Accepts the public beta key, validates user agent.
    Production mode: Validates per-user API keys.
    
    Returns the API key string if valid.
    """
    # Beta mode: allow public beta key
    if _is_beta_mode():
        if api_key == BETA_KEY:
            logger.debug("Beta API key used")
            return BETA_KEY
        
        # In beta mode, we still require the beta key (no anonymous access)
        if api_key is None:
            raise HTTPException(
                status_code=401, 
                detail="Missing X-API-Key header. Use beta key: phishscamsense-beta-2024-public"
            )
        
        if api_key != BETA_KEY:
            raise HTTPException(
                status_code=403, 
                detail=f"Invalid API key. Use beta key: {BETA_KEY}"
            )
        
        return BETA_KEY
    
    # Production mode: validate against configured keys
    if not settings.API_KEYS:
        raise HTTPException(
            status_code=503, 
            detail="API keys not configured. See README.md for setup instructions."
        )
    
    if api_key is None:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    
    if api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    return api_key


async def get_api_key_optional(api_key: str = Security(api_key_header)) -> str | None:
    """
    Optional authentication — used for endpoints that should remain
    accessible without auth (e.g. /health) but still validate keys if present.
    """
    if api_key is None:
        return None
    
    if _is_beta_mode():
        if api_key != BETA_KEY:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return BETA_KEY
    
    if settings.API_KEYS and api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    return api_key


async def get_api_key_with_ua_check(
    api_key: str = Security(api_key_header),
    user_agent: str = None
) -> str:
    """
    Authentication with user agent validation (anti-abuse).
    
    Use this for endpoints where you want to ensure requests come from
    legitimate clients (browser extensions) rather than scripts.
    """
    # First validate API key
    validated_key = await get_api_key(api_key)
    
    # Then validate user agent (if configured)
    if user_agent and not _is_valid_user_agent(user_agent):
        logger.warning(f"Blocked request from disallowed user agent: {user_agent}")
        raise HTTPException(
            status_code=403,
            detail="User agent not allowed. Use the browser extension."
        )
    
    return validated_key
```

---

### **STEP 3: Enhanced Rate Limiting**

#### File: `backend/app/core/rate_limit.py` (UPDATE)

```python
"""
Rate limiting configuration using slowapi.

Beta mode: Rate limiting per IP address (since all users share the beta key).
Production mode: Rate limiting per API key (per-user limits).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


def _get_identifier(request) -> str:
    """
    Rate limit identifier based on mode.
    
    Beta mode: Per IP address (since all users share the beta key)
    Production mode: Per API key (per-user)
    """
    if settings.BETA_MODE:
        # Beta mode: rate limit per IP
        return f"ip:{get_remote_address(request)}"
    else:
        # Production mode: rate limit per API key
        api_key = request.headers.get("X-API-Key", "anonymous")
        if api_key and api_key != "anonymous":
            return f"key:{api_key}"
        return f"ip:{get_remote_address(request)}"


# Create limiter with mode-aware identifier
limiter = Limiter(
    key_func=_get_identifier, 
    default_limits=["60/minute"]  # Conservative default
)
```

---

### **STEP 4: Telemetry Module**

#### File: `backend/app/core/telemetry.py` (NEW FILE)

```python
"""
Telemetry module for beta phase.

Logs usage patterns WITHOUT PII (Personally Identifiable Information).
Helps understand how the service is being used during beta testing.

Telemetry data:
- Request counts (per endpoint, per hour/day)
- URL patterns tested (domain only, not full URL)
- User agent statistics
- Geographic distribution (country level from IP)
- Error rates
- Performance metrics

NOT collected:
- Full URLs (potential PII)
- IP addresses
- User identifiers
- Timestamps (only aggregated counts)
"""

import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from fastapi import Request

from app.core.config import settings

logger = logging.getLogger(__name__)


class TelemetryLogger:
    """Log usage telemetry without PII."""
    
    def __init__(self, log_dir: Path = Path("/var/log/phishscamsense")):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.telemetry_file = self.log_dir / "telemetry.ndjson"
        
        logger.info(f"Telemetry initialized: {self.telemetry_file}")
    
    def is_enabled(self) -> bool:
        """Check if telemetry is enabled."""
        return settings.ENABLE_TELEMETRY
    
    def should_sample(self) -> bool:
        """Determine if this request should be sampled (for rate limiting high-volume telemetry)."""
        import random
        return random.random() < settings.TELEMETRY_SAMPLE_RATE
    
    def log_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        duration_ms: int,
        user_agent: str | None = None,
        country: str | None = None,
        error: str | None = None
    ):
        """Log a request (sampled if telemetry rate is high)."""
        if not self.is_enabled():
            return
        
        if not self.should_sample():
            return
        
        # Hash URL domain for privacy (don't log full URLs)
        # Extract domain from request if available
        domain = "unknown"
        
        try:
            import json
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "hour": datetime.now(timezone.utc).strftime("%H"),
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "domain_hash": hashlib.sha256(domain.encode()).hexdigest()[:16],
                "user_agent_type": self._classify_user_agent(user_agent),
                "country": country or "unknown",
                "error": error,
            }
            
            # Append to telemetry log
            with open(self.telemetry_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        
        except Exception as e:
            logger.error(f"Failed to write telemetry: {e}")
    
    def _classify_user_agent(self, user_agent: str | None) -> str:
        """Classify user agent into broad categories."""
        if not user_agent:
            return "unknown"
        
        ua_lower = user_agent.lower()
        
        if "chrome-extension" in ua_lower or "moz-extension" in ua_lower:
            return "extension"
        elif "mozilla/5.0" in ua_lower:
            return "browser"
        elif "curl" in ua_lower or "python" in ua_lower or "requests" in ua_lower:
            return "script"
        else:
            return "other"


# Global telemetry logger instance
telemetry = TelemetryLogger()


def get_country_from_ip(request: Request) -> str | None:
    """
    Extract country from IP address (for telemetry).
    
    This is a simple implementation that uses GeoIP if available.
    For production, consider using a proper GeoIP database.
    """
    # Simple implementation: extract from Cloudflare/AWS headers if present
    cf_ipcountry = request.headers.get("cf-ipcountry")
    if cf_ipcountry:
        return cf_ipcountry
    
    aws_cloudfront_viewer_country = request.headers.get("x-amz-cf-id")
    if aws_cloudfront_viewer_country:
        return aws_cloudfront_viewer_country
    
    # Fallback: return None (no country data)
    return None


def log_telemetry_middleware(endpoint: str):
    """FastAPI dependency that logs telemetry for an endpoint."""
    async def middleware(
        request: Request,
        call_next
    ):
        start_time = datetime.now(timezone.utc)
        
        try:
            response = await call_next(request)
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            # Log successful request
            telemetry.log_request(
                endpoint=endpoint,
                method=request.method,
                status_code=response.status_code,
                duration_ms=duration_ms,
                user_agent=request.headers.get("user-agent"),
                country=get_country_from_ip(request)
            )
            
            return response
        
        except Exception as e:
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            # Log error
            telemetry.log_request(
                endpoint=endpoint,
                method=request.method,
                status_code=500,
                duration_ms=duration_ms,
                user_agent=request.headers.get("user-agent"),
                country=get_country_from_ip(request),
                error=str(e)[:100]  # First 100 chars of error
            )
            
            raise
    
    return middleware
```

---

### **STEP 5: Update Main Application**

#### File: `backend/app/main.py` (UPDATE)

```python
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import predict, reports, threats
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.rate_limit import limiter
from app.core.request_logger import RequestLoggerMiddleware
from app.core.security import get_api_key, get_api_key_optional
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.telemetry import log_telemetry_middleware, telemetry
from app.services.ml_predictor import get_predictor

setup_logging()
logger = logging.getLogger(__name__)

# Resolve exports path relative to this file's location
_HERE = Path(__file__).resolve().parent
_BACKEND_ROOT = _HERE.parent
_PROJECT_ROOT = _BACKEND_ROOT.parent


def _resolve_exports_dir() -> Path:
    """Return the absolute path to ml/exports/."""
    configured = Path(settings.MODEL_EXPORTS_PATH)
    if configured.is_absolute():
        return configured
    candidate = _PROJECT_ROOT / configured
    if candidate.exists():
        return candidate
    return Path.cwd() / configured


@asynccontextmanager
async def lifespan(_app: FastAPI):
    exports_dir = _resolve_exports_dir()
    if exports_dir.exists():
        try:
            get_predictor(exports_dir)
            logger.info("ML models loaded from %s", exports_dir)
        except Exception as exc:
            logger.warning("Could not load ML models from %s: %s", exports_dir, exc)
    else:
        logger.warning(
            "MODEL_EXPORTS_PATH '%s' (resolved: %s) does not exist — predictions disabled",
            settings.MODEL_EXPORTS_PATH,
            exports_dir,
        )
    
    # Log beta mode status
    if settings.BETA_MODE:
        logger.info("🔓 Running in BETA MODE - Public API key enabled")
        logger.info("   Beta Key: %s", settings.API_KEYS[0] if settings.API_KEYS else "None")
        logger.info("   Telemetry: %s", "ENABLED" if settings.ENABLE_TELEMETRY else "DISABLED")
        logger.info("   Rate Limiting: Per-IP")
    else:
        logger.info("🔒 Running in PRODUCTION MODE - Per-user API keys")
    
    yield


app = FastAPI(
    title="PhishScamSense API",
    description="Real-Time Multimodal Phishing Defense Backend",
    version="0.2.0-beta",
    lifespan=lifespan,
    docs_url="/docs" if settings.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if settings.DOCS_ENABLED else None,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Request/response logging (innermost — runs closest to route handler)
app.add_middleware(RequestLoggerMiddleware)

# Telemetry (if enabled)
if settings.ENABLE_TELEMETRY:
    logger.info("📊 Telemetry enabled - logging usage patterns (no PII)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"(chrome-extension|moz-extension)://.*" if settings.CORS_ALLOW_EXTENSION_ORIGINS else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# Include routers with telemetry
app.include_router(
    predict.router, 
    prefix="/api/v1", 
    tags=["prediction"],
    dependencies=[Depends(log_telemetry_middleware("/api/v1/predict"))]
)
app.include_router(
    threats.router, 
    prefix="/api/v1", 
    tags=["threats"],
    dependencies=[Depends(log_telemetry_middleware("/api/v1/threats/bloom-filter"))]
)
app.include_router(
    reports.router, 
    prefix="/api/v1", 
    tags=["reports"],
    dependencies=[Depends(log_telemetry_middleware("/api/v1/reports/false-positive"))]
)


@app.get("/health")
async def health_check(api_key: str | None = Depends(get_api_key_optional)):
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": get_predictor() is not None,
        "beta_mode": settings.BETA_MODE,
        "telemetry_enabled": settings.ENABLE_TELEMETRY,
        "version": "0.2.0-beta"
    }


@app.get("/beta-info")
async def beta_info():
    """Beta mode information - public endpoint with usage instructions."""
    return {
        "beta_mode": settings.BETA_MODE,
        "beta_key": settings.API_KEYS[0] if settings.BETA_MODE and settings.API_KEYS else None,
        "docs_url": "/docs" if settings.DOCS_ENABLED else None,
        "extension_install_url": "https://github.com/penanamtomat/PhishScamSense#browser-extension",
        "usage": {
            "api_key": settings.API_KEYS[0] if settings.BETA_MODE and settings.API_KEYS else None,
            "endpoint": "/api/v1/predict",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "X-API-Key": settings.API_KEYS[0] if settings.BETA_MODE and settings.API_KEYS else None
            },
            "body": {
                "url": "https://example.com",
                "html": "<html>...</html>"  # optional
            }
        },
        "rate_limits": {
            "predict": settings.RATE_LIMIT_PREDICT,
            "reports": settings.RATE_LIMIT_REPORTS,
            "threats": settings.RATE_LIMIT_THREATS
        },
        "privacy": {
            "telemetry": "Enabled" if settings.ENABLE_TELEMETRY else "Disabled",
            "telemetry_note": "We log usage patterns without PII to improve the service",
            "full_urls": "NOT logged (only domain hashes)",
            "ip_addresses": "NOT logged"
        }
    }
```

---

### **STEP 6: Update .env.example**

#### File: `backend/.env.example` (UPDATE)

```bash
# Copy this file to .env and fill in your values
# DO NOT commit .env to git

# =============================================================================
# BETA MODE CONFIGURATION
# =============================================================================

# Beta mode: Single public API key for all beta users
BETA_MODE=true
API_KEYS=["phishscamsense-beta-2024-public"]

# Telemetry: Log usage patterns without PII (recommended for beta)
ENABLE_TELEMETRY=true
TELEMETRY_SAMPLE_RATE=0.1  # Log 10% of requests

# =============================================================================
# API AUTHENTICATION (PRODUCTION MODE - Future Use)
# =============================================================================

# For production, you'll generate individual API keys per user
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
# API_KEYS=["user1-key-here", "user2-key-here"]

# =============================================================================
# PATHS
# =============================================================================

# Path to the trained XGBoost model (relative to project root)
MODEL_EXPORTS_PATH=ml/exports

# =============================================================================
# SWAGGER UI
# =============================================================================

# Swagger UI — set to false in production to disable /docs and /openapi.json
DOCS_ENABLED=true

# =============================================================================
# CORS
# =============================================================================

# CORS — explicit list of allowed origins (JSON array, no wildcard).
# Browser extension origins are handled separately via CORS_ALLOW_EXTENSION_ORIGINS.
# Example: CORS_ORIGINS=["https://phishscam.my.id"]
CORS_ORIGINS=[]

# Allow chrome-extension:// and moz-extension:// origins
CORS_ALLOW_EXTENSION_ORIGINS=true

# =============================================================================
# RATE LIMITING
# =============================================================================

# Rate limiting (requests per minute per IP in beta mode)
RATE_LIMIT_PREDICT=60/minute;1000/hour
RATE_LIMIT_REPORTS=10/minute;100/day
RATE_LIMIT_THREATS=100/second;10000/hour

# =============================================================================
# USER AGENT WHITELIST (Optional Anti-Abuse)
# =============================================================================

# Only allow requests from these user agents (leave empty to allow all)
# Format: substring match (case-insensitive)
ALLOWED_USER_AGENTS=["Mozilla/5.0", "PhishScamSense-Extension"]

# =============================================================================
# OPTIONAL: Third-party Threat Intelligence APIs
# =============================================================================

VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
PHISHTANK_API_KEY=

# =============================================================================
# OPTIONAL: MLflow
# =============================================================================

MLFLOW_TRACKING_URI=http://localhost:5000
```

---

### **STEP 7: Update Extension Configuration**

#### File: `extension/entrypoints/background.ts` (UPDATE)

```typescript
export default defineBackground(async () => {
  console.log("PhishScamSense background service worker started");

  // Persist the resolved apiBase so static pages (blocked.html) can read it
  const stored = await browser.storage.local.get("apiBase");
  if (!stored.apiBase) {
    const resolved = import.meta.env.WXT_API_BASE || "http://localhost:8000";
    await browser.storage.local.set({ apiBase: resolved });
  }

  // NEW: Persist the beta API key
  const keyStored = await browser.storage.local.get("apiKey");
  if (!keyStored.apiKey) {
    // Default beta key - can be overridden by user
    const betaKey = import.meta.env.WXT_API_KEY || "phishscamsense-beta-2024-public";
    await browser.storage.local.set({ apiKey: betaKey });
    console.log("Beta API key configured:", betaKey);
  }

  // ... rest of the code remains the same ...
```

---

### **STEP 8: Update README**

#### File: `README.md` (ADD SECTION)

```markdown
## 🚀 Quick Start for Beta Users

### For Browser Extension Users

1. Install the PhishScamSense browser extension
2. The extension is pre-configured with the beta API key
3. Start browsing - protection is automatic!

### For API Users

**API Endpoint:** `https://phishscam.my.id/api/v1/predict`

**Beta API Key:** `phishscamsense-beta-2024-public`

```bash
curl -X POST https://phishscam.my.id/api/v1/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: phishscamsense-beta-2024-public" \
  -d '{
    "url": "https://example.com",
    "html": "<html>...</html>"
  }'
```

### Beta Mode Features

✅ **No registration required** - Just use the beta key  
✅ **Rate limited** - 60 requests/minute per IP  
✅ **Full access** - All API endpoints available  
✅ **Telemetry enabled** - Helps us improve the service  

### Rate Limits

- **Predict:** 60/minute, 1000/hour (per IP)
- **Reports:** 10/minute, 100/day (per IP)
- **Threats:** 100/second, 10,000/hour (per IP)

### Privacy

We collect telemetry data to improve the service during beta:
- ✅ Usage patterns (requests per endpoint)
- ✅ Domain hashes (not full URLs)
- ✅ User agent types
- ✅ Geographic distribution
- ❌ NO IP addresses
- ❌ NO full URLs
- ❌ NO personal data

---

## 🔮 Future Migration Path: Account System

### Phase 1: Open Beta (CURRENT)
- Single public API key for all users
- Rate limiting per IP
- Basic telemetry

### Phase 2: Soft Account (1-2 Months)
- Email verification required
- Free API key per user
- Enhanced telemetry
- User dashboard

### Phase 3: Tiered Access (Future)
- Free tier: Limited requests
- Pro tier: Higher limits
- Enterprise: Unlimited + support

---

## 📊 Telemetry Dashboard (Optional)

During beta, you can analyze telemetry data:

```bash
# View request counts by endpoint
cat /var/log/phishscamsense/telemetry.ndjson | \
  jq -r '.endpoint' | sort | uniq -c

# View user agent distribution
cat /var/log/phishscamsense/telemetry.ndjson | \
  jq -r '.user_agent_type' | sort | uniq -c

# View geographic distribution
cat /var/log/phishscamsense/telemetry.ndjson | \
  jq -r '.country' | sort | uniq -c

# View error rates
cat /var/log/phishscamsense/telemetry.ndjson | \
  jq 'select(.error) | .endpoint' | sort | uniq -c
```

---

## 🎯 Benefits of This Approach

### For Users (Beta Testers)
✅ **No registration barrier** - Start using immediately  
✅ **Full functionality** - All features available  
✅ **Transparent** - Clear documentation  
✅ **Privacy respected** - No PII collected  

### For You (Service Owner)
✅ **Abuse control** - Rate limiting per IP  
✅ **Telemetry data** - Understand usage patterns  
✅ **User agent filtering** - Block script abuse  
✅ **Migration ready** - Path to account system  
✅ **Production-like** - Test auth flow with real key  

### For Future Monetization
✅ **Easy transition** - Users already understand API keys  
✅ **Usage patterns** - Know how people use the service  
✅ **Abuse patterns** - Know what to block  
✅ **Communication channel** - Can email users  

---

## 🚨 Anti-Abuse Measures

### 1. Rate Limiting
```python
# Already configured in settings
RATE_LIMIT_PREDICT = "60/minute;1000/hour"  # Per IP in beta mode
```

### 2. User Agent Filtering
```python
# Block suspicious user agents
ALLOWED_USER_AGENTS = [
    "Mozilla/5.0",  # Browser extension
    "PhishScamSense-Extension"
]
```

### 3. Telemetry Sampling
```python
# Only log 10% of requests to reduce load
TELEMETRY_SAMPLE_RATE = 0.1
```

### 4. Geographic Blocking (Optional)
```python
# Can add country blocking if abuse detected from certain regions
BLOCKED_COUNTRIES = []  # Empty = no blocking
```

---

## 📝 Implementation Checklist

### Phase 1: Core Implementation (2 hours)
- [ ] Update `backend/app/core/config.py` with new settings
- [ ] Update `backend/app/core/security.py` with beta mode logic
- [ ] Update `backend/app/core/rate_limit.py` with beta mode logic
- [ ] Create `backend/app/core/telemetry.py` module
- [ ] Update `backend/app/main.py` with telemetry
- [ ] Update `backend/.env.example` with beta settings

### Phase 2: Testing (1 hour)
- [ ] Test API with beta key
- [ ] Test rate limiting
- [ ] Test telemetry logging
- [ ] Test user agent filtering
- [ ] Test extension with new key

### Phase 3: Documentation (30 minutes)
- [ ] Update README.md with beta instructions
- [ ] Create `BETA-USAGE.md` guide
- [ ] Update extension README
- [ ] Create migration guide for users

### Phase 4: Deployment (30 minutes)
- [ ] Set environment variables
- [ ] Deploy to production
- [ ] Verify beta mode is active
- [ ] Test all endpoints
- [ ] Monitor telemetry logs

---

## 🔧 Quick Start Commands

```bash
# 1. Update code
cd /home/dimas/Projects/PhishScamSense/backend

# 2. Create/update .env file
cat > .env << 'EOF'
BETA_MODE=true
API_KEYS=["phishscamsense-beta-2024-public"]
ENABLE_TELEMETRY=true
TELEMETRY_SAMPLE_RATE=0.1
DOCS_ENABLED=true
RATE_LIMIT_PREDICT=60/minute;1000/hour
RATE_LIMIT_REPORTS=10/minute;100/day
RATE_LIMIT_THREATS=100/second;10000/hour
ALLOWED_USER_AGENTS=["Mozilla/5.0"]
EOF

# 3. Restart the application
docker-compose down
docker-compose up --build

# 4. Verify beta mode
curl https://phishscam.my.id/beta-info
```

---

## 📈 Monitoring & Analytics

### Key Metrics to Track

1. **Usage Metrics**
   - Requests per day
   - Unique IPs per day
   - Peak usage times

2. **Performance Metrics**
   - Response time (p50, p95, p99)
   - Error rate
   - Rate limit hits

3. **User Behavior**
   - Most tested domains (hashed)
   - User agent distribution
   - Geographic distribution

4. **Security Metrics**
   - Blocked requests (abuse attempts)
   - Rate limit violations
   - Suspicious patterns

---

## 🎓 Conclusion

This **Middle Ground Approach** memberikan Anda kontrol yang cukup untuk fase beta sambil:

✅ **Mempertahankan user experience yang mudah**  
✅ **Mengumpul data berharga untuk improvement**  
✅ **Mempersiapkan migrasi ke model bisnis**  
✅ **Melindungi service dari abuse**  
✅ **Tetap transparan tentang privacy**  

**Ini adalah win-win solution untuk beta testing phase!**

---

## 📞 Next Steps

Apakah Anda ingin saya:
1. Implementasi perubahan kode di atas?
2. Buat telemetry dashboard?
3. Buat migration guide ke account system?
4. Test implementasi di staging environment?
