"""Session Manager: Multi-Role Authentication and Token Lifecycle.

Manages test personas (Anonymous, User A, User B, Admin), automates login
against the target application, and stores ephemeral tokens in memory.
"""

from typing import Dict, Optional
from enum import Enum
from pydantic import BaseModel
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class Role(str, Enum):
    """Supported test roles for authorization-differential testing."""
    ANONYMOUS = "anonymous"
    USER_A = "user_a"       # Low-privilege victim/baseline
    USER_B = "user_b"       # Low-privilege attacker/peer
    ADMIN = "admin"         # Elevated administrator


class RoleSession(BaseModel):
    """Session credentials and authentication headers for a role."""
    role: Role
    email: Optional[str] = None
    token: Optional[str] = None
    cookies: Dict[str, str] = {}
    is_authenticated: bool = False


class SessionManager:
    """Coordinates authentication and header generation for all testing personas."""

    def __init__(self):
        self._sessions: Dict[Role, RoleSession] = {
            Role.ANONYMOUS: RoleSession(role=Role.ANONYMOUS, is_authenticated=True)
        }

    def authenticate_role(self, role: Role, email: str, password: str) -> RoleSession:
        """Authenticates a test persona against OWASP Juice Shop.

        TODO (Phase 2): Implement Juice Shop `/api/Users/login` POST request
        and extract returned Bearer token.
        """
        logger.info("Authenticating role persona", extra={"role": role.value, "email": email})
        session = RoleSession(
            role=role,
            email=email,
            token="placeholder_jwt_token",
            is_authenticated=True
        )
        self._sessions[role] = session
        return session

    def get_auth_headers(self, role: Role) -> Dict[str, str]:
        """Returns HTTP authentication headers for the requested role."""
        session = self._sessions.get(role)
        if not session or not session.token:
            return {}
        return {"Authorization": f"Bearer {session.token}"}

