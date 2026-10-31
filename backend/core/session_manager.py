"""Session Manager: Multi-Role Session Containers, Identity Isolation & Auth Adapter.

Maintains strictly isolated session state (Bearer tokens, cookies, email identifiers,
and verified owned resource identifiers) for distinct test personas:
- Anonymous: Unauthenticated baseline persona
- User A: Low-privilege baseline/owner persona
- User B: Low-privilege peer persona
- Admin: High-privilege tenant administrator persona

Credentials and tokens are loaded from environment configurations or obtained via
an explicit AuthenticationAdapter. Never invents credentials or resource ownership.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set
from enum import Enum
from pydantic import BaseModel, Field

from backend.config import settings
from backend.utils.helpers import MissingSessionError, SessionAuthenticationError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class Role(str, Enum):
    """Supported test roles for authorization-differential testing."""
    ANONYMOUS = "anonymous"
    USER_A = "user_a"       # Low-privilege resource owner / baseline
    USER_B = "user_b"       # Low-privilege peer account
    ADMIN = "admin"         # High-privilege administrator


class AuthCredentials(BaseModel):
    """Configured credentials for a test account loaded from environment."""
    email: Optional[str] = None
    password: Optional[str] = Field(default=None, repr=False)


class AuthenticationResult(BaseModel):
    """Structured result returned by an AuthenticationAdapter."""
    is_authenticated: bool
    token: Optional[str] = None
    cookies: Dict[str, str] = Field(default_factory=dict)
    user_id: Optional[str] = None
    owned_resources: Dict[str, List[str]] = Field(default_factory=dict)
    error_message: Optional[str] = None


class AuthenticationAdapter(ABC):
    """Abstract adapter interface for authenticating test roles against a target.

    Implementations of this interface execute real target authentication flows
    (when POST/login routes are enabled) or retrieve pre-provisioned tokens from
    a secure vault. It must never fabricate or guess authentication sessions.
    """

    @abstractmethod
    def authenticate(self, role: Role, credentials: AuthCredentials) -> AuthenticationResult:
        """Authenticates a role using configured credentials and returns session material."""
        raise NotImplementedError


class EnvTokenAuthenticationAdapter(AuthenticationAdapter):
    """Default safe adapter that reads pre-configured session tokens from environment.

    Does not make destructive or mutating POST requests and never invents tokens.
    If no token is present in the environment for the requested role, returns
    `is_authenticated=False`.
    """

    def __init__(self, role_tokens: Optional[Dict[Role, str]] = None):
        self._tokens: Dict[Role, str] = role_tokens or {
            Role.USER_A: settings.user_a_token,
            Role.USER_B: settings.user_b_token,
            Role.ADMIN: settings.admin_token,
        }

    def authenticate(self, role: Role, credentials: AuthCredentials) -> AuthenticationResult:
        if role == Role.ANONYMOUS:
            return AuthenticationResult(is_authenticated=True)

        token = (self._tokens.get(role) or "").strip()
        if not token:
            return AuthenticationResult(
                is_authenticated=False,
                error_message=(
                    f"No pre-configured session token found in environment for role '{role.value}'. "
                    f"Configure {role.value.upper()}_TOKEN in .env or provide an active session token."
                )
            )
        return AuthenticationResult(
            is_authenticated=True,
            token=token
        )


class RoleSession(BaseModel):
    """Container representing an isolated authenticated session state."""
    role: Role
    email: Optional[str] = None
    user_id: Optional[str] = Field(default=None, description="Verified account user ID if known")
    token: Optional[str] = Field(default=None, repr=False, description="Bearer JWT token")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Session cookies")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom role headers")
    owned_resources: Dict[str, Set[str]] = Field(
        default_factory=dict,
        description="Explicitly registered resource IDs owned by this role (e.g. {'basket': {'1'}})"
    )
    is_authenticated: bool = False

    def get_headers(self) -> Dict[str, str]:
        """Constructs headers for HTTP execution without exposing raw tokens in logs."""
        headers: Dict[str, str] = dict(self.custom_headers)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        return headers

    def register_owned_resource(self, resource_type: str, resource_id: str) -> None:
        """Registers an explicitly known resource ID owned by this role."""
        key = resource_type.strip().lower()
        if key not in self.owned_resources:
            self.owned_resources[key] = set()
        self.owned_resources[key].add(str(resource_id).strip())

    def owns_resource(self, resource_type: str, resource_id: str) -> bool:
        """Checks whether this role is the registered owner of a specific resource ID."""
        key = resource_type.strip().lower()
        return str(resource_id).strip() in self.owned_resources.get(key, set())


class SessionManager:
    """Manages role sessions, credential bindings, token isolation, and header generation."""

    def __init__(
        self,
        load_from_env: bool = True,
        auth_adapter: Optional[AuthenticationAdapter] = None
    ):
        """Initializes separate session containers for Anonymous, User A, User B, and Admin."""
        self._sessions: Dict[Role, RoleSession] = {}
        self._credentials: Dict[Role, AuthCredentials] = {}
        self._auth_adapter: AuthenticationAdapter = auth_adapter or EnvTokenAuthenticationAdapter()
        self._init_containers(load_from_env=load_from_env)

    def _init_containers(self, load_from_env: bool = True) -> None:
        """Initializes isolated containers for all supported roles from env settings."""
        # Anonymous is always available with empty credentials
        self._sessions[Role.ANONYMOUS] = RoleSession(
            role=Role.ANONYMOUS,
            is_authenticated=True
        )
        self._credentials[Role.ANONYMOUS] = AuthCredentials()

        # Role configuration map from settings (never hardcoded)
        env_role_map = {
            Role.USER_A: (
                settings.user_a_email if load_from_env else None,
                settings.user_a_password if load_from_env else None,
                settings.user_a_token.strip() if load_from_env and settings.user_a_token else None,
            ),
            Role.USER_B: (
                settings.user_b_email if load_from_env else None,
                settings.user_b_password if load_from_env else None,
                settings.user_b_token.strip() if load_from_env and settings.user_b_token else None,
            ),
            Role.ADMIN: (
                settings.admin_email if load_from_env else None,
                settings.admin_password if load_from_env else None,
                settings.admin_token.strip() if load_from_env and settings.admin_token else None,
            ),
        }

        for role, (email, password, token) in env_role_map.items():
            self._credentials[role] = AuthCredentials(email=email, password=password)
            sess = RoleSession(
                role=role,
                email=email,
                token=token,
                is_authenticated=bool(token)
            )
            self._sessions[role] = sess

    def validate_configured_credentials(self) -> Dict[str, Any]:
        """Validates configured role credentials and tokens from environment without exposing secrets.

        Returns:
            Dict containing credential health, role status, and multi-role readiness.
        """
        user_a_ready = self.is_authenticated(Role.USER_A)
        user_b_ready = self.is_authenticated(Role.USER_B)
        admin_ready = self.is_authenticated(Role.ADMIN)

        return {
            "user_a_authenticated": user_a_ready,
            "user_b_authenticated": user_b_ready,
            "admin_authenticated": admin_ready,
            "multi_role_ready": user_a_ready and user_b_ready,
            "authenticated_roles": [
                r.value for r in (Role.USER_A, Role.USER_B, Role.ADMIN)
                if self.is_authenticated(r)
            ],
            "anonymous_baseline_ready": True,
        }

    def get_session(self, role: Role | str) -> RoleSession:
        """Retrieves the session container for the specified role.

        Raises:
            MissingSessionError: If the role is unknown or not supported.
        """
        try:
            role_enum = Role(role) if isinstance(role, str) else role
        except ValueError as exc:
            raise MissingSessionError(f"Unsupported testing role: '{role}'") from exc

        if role_enum not in self._sessions:
            raise MissingSessionError(f"No session container initialized for role '{role_enum}'")

        return self._sessions[role_enum]

    def require_authenticated_session(self, role: Role | str) -> RoleSession:
        """Retrieves a role session and verifies it has active authentication material.

        For non-anonymous roles, raises MissingSessionError if the role does not have
        a configured token or session cookie. Never invents a session.
        """
        session = self.get_session(role)
        if session.role == Role.ANONYMOUS:
            return session

        if not session.is_authenticated or (not session.token and not session.cookies):
            raise MissingSessionError(
                f"Role '{session.role.value}' does not have an active authenticated session. "
                f"Configure a valid token or authenticate via AuthenticationAdapter before testing."
            )
        return session

    def authenticate_with_adapter(
        self,
        role: Role | str,
        adapter: Optional[AuthenticationAdapter] = None
    ) -> RoleSession:
        """Authenticates a role using the provided or default AuthenticationAdapter.

        Raises:
            SessionAuthenticationError: If the adapter cannot authenticate the role.
        """
        session = self.get_session(role)
        if session.role == Role.ANONYMOUS:
            return session

        active_adapter = adapter or self._auth_adapter
        creds = self._credentials.get(session.role, AuthCredentials(email=session.email))
        result = active_adapter.authenticate(session.role, creds)

        if not result.is_authenticated:
            session.is_authenticated = False
            raise SessionAuthenticationError(
                result.error_message or f"Authentication failed for role '{session.role.value}'."
            )

        session.token = result.token
        if result.cookies:
            session.cookies.update(result.cookies)
        if result.user_id:
            session.user_id = result.user_id
        for res_type, res_ids in result.owned_resources.items():
            for rid in res_ids:
                session.register_owned_resource(res_type, rid)

        session.is_authenticated = True
        logger.info("Authenticated role session via adapter", extra={"role": session.role.value})
        return session

    def authenticate_role(
        self,
        role: Role | str,
        email: str,
        password: str,
        token: Optional[str] = None
    ) -> RoleSession:
        """Configures test session credentials for a role persona in controlled tests."""
        session = self.get_session(role)
        session.email = email
        self._credentials[session.role] = AuthCredentials(email=email, password=password)
        if token is not None:
            session.token = token.strip() or None
        session.is_authenticated = bool(session.token or session.cookies)
        logger.info("Configured role session credentials", extra={"role": session.role.value})
        return session

    def set_token(
        self,
        role: Role | str,
        token: str,
        user_id: Optional[str] = None
    ) -> None:
        """Assigns an authentication token to a specific role session."""
        session = self.get_session(role)
        session.token = token.strip()
        if user_id is not None:
            session.user_id = str(user_id).strip()
        session.is_authenticated = bool(session.token or session.cookies)
        logger.info("Updated role authentication token", extra={"role": session.role.value})

    def set_cookie(self, role: Role | str, name: str, value: str) -> None:
        """Assigns a cookie to a specific role session."""
        session = self.get_session(role)
        session.cookies[name] = value
        session.is_authenticated = bool(session.token or session.cookies)
        logger.info("Updated role cookie", extra={"role": session.role.value, "cookie_name": name})

    def register_resource_ownership(
        self,
        role: Role | str,
        resource_type: str,
        resource_id: str
    ) -> None:
        """Explicitly records that a role owns a specific resource identifier."""
        session = self.get_session(role)
        session.register_owned_resource(resource_type, resource_id)

    def set_credentials(
        self,
        role: Role | str,
        email: str,
        token: Optional[str] = None,
        password: Optional[str] = None
    ) -> None:
        """Configures credentials for a role without inventing tokens."""
        session = self.get_session(role)
        session.email = email
        self._credentials[session.role] = AuthCredentials(email=email, password=password)
        if token:
            session.token = token.strip()
            session.is_authenticated = True

    def get_auth_headers(self, role: Role | str) -> Dict[str, str]:
        """Returns the HTTP headers required for authenticating requests as this role."""
        session = self.get_session(role)
        return session.get_headers()

    def is_authenticated(self, role: Role | str) -> bool:
        """Returns True if the role has an active authentication session."""
        session = self.get_session(role)
        return session.is_authenticated
