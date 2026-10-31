"""In-body authorization helpers for cross-file static analysis testing."""

from fastapi import HTTPException


def verify_admin_access(user_role: str) -> None:
    """In-body authorization verification function."""
    if user_role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Admin role required",
        )

