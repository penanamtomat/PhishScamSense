"""
Request/response logging middleware.

Logs every request with method, path, status, duration, IP, body size, req_id.

Example:
  INFO     [2026-04-13 12:00:01] app.core.request_logger — POST /api/v1/predict 200 | 142ms | ip=1.2.3.4 | body=4821B | req_id=a1b2c3d4
  ERROR    [2026-04-13 12:00:02] app.core.request_logger — POST /api/v1/predict 500 | 23ms  | ip=1.2.3.4 | body=98432B | req_id=e5f6g7h8
"""
import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = uuid.uuid4().hex[:8]
        request.state.req_id = req_id
        start = time.perf_counter()

        forwarded_for = request.headers.get("X-Forwarded-For")
        client_ip = (
            forwarded_for.split(",")[0].strip()
            if forwarded_for
            else (request.client.host if request.client else "unknown")
        )

        body_size = request.headers.get("Content-Length", "?")

        response = await call_next(request)

        duration_ms = int((time.perf_counter() - start) * 1000)
        status = response.status_code
        msg = (
            f"{request.method} {request.url.path} {status}"
            f" | {duration_ms}ms | ip={client_ip}"
            f" | body={body_size}B | req_id={req_id}"
        )

        if status >= 500:
            logger.error(msg)
        elif status >= 400:
            logger.warning(msg)
        else:
            logger.info(msg)

        response.headers["X-Request-ID"] = req_id
        return response
