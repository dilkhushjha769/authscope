"""FastAPI security dependencies for cross-file static analysis testing."""

from typing import Dict
from fastapi import HTTPException, Header, status


async def get_current_admin(authorization: str = Header(None)) -> Dict[str, str]:
    """FastAPI dependency verifying admin role."""
    if not authorization or "admin" not in authorization.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin authorization required",
        )
    return {"role": "admin"}

