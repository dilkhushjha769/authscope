"""Global security middleware for cross-file static analysis testing."""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response


class GlobalSecurityMiddleware(BaseHTTPMiddleware):
    """Global authentication & authorization security middleware."""

    async def dispatch(self, request: Request, call_next) -> Response:
        return await call_next(request)

