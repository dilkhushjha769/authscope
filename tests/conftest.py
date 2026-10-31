"""Pytest configuration and shared test fixtures for AuthScope."""

from typing import Dict, Any
import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.api.security import assessment_creation_limiter


@pytest.fixture
def scope_guard() -> ScopeGuard:
    """Provides a ScopeGuard instance locked strictly to localhost:3000 and GET method."""
    return ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http"],
        allowed_methods=["GET"]
    )


@pytest.fixture
def session_manager() -> SessionManager:
    """Provides a cleanly initialized SessionManager without external env dependencies."""
    mgr = SessionManager(load_from_env=False)
    # Configure test tokens
    mgr.set_token(Role.USER_A, "mocked_jwt_user_a")
    mgr.set_token(Role.USER_B, "mocked_jwt_user_b")
    mgr.set_token(Role.ADMIN, "mocked_jwt_admin")
    return mgr


@pytest.fixture
def mock_juice_shop_transport() -> httpx.MockTransport:
    """Provides an httpx MockTransport simulating OWASP Juice Shop responses."""
    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)

        # Simulate 302 Redirect to test redirect suppression
        if "/redirect-test" in url_str:
            return httpx.Response(
                status_code=302,
                headers={"Location": "http://localhost:3000/login", "Content-Type": "text/plain"},
                content=b"Redirecting to /login"
            )

        # Simulate standard API endpoints
        if "/rest/admin/application-version" in url_str:
            auth_header = request.headers.get("Authorization", "")
            if "mocked_jwt_admin" in auth_header:
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    json={"version": "17.1.1"}
                )
            return httpx.Response(status_code=403, json={"error": "Access Denied"})

        if "/rest/basket/1" in url_str:
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                json={"data": {"id": 1, "UserId": 1, "items": [{"id": 42, "name": "Apple Juice"}]}}
            )

        # Default fallback: 200 OK
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"<html><body>OWASP Juice Shop Mock</body></html>"
        )

    return httpx.MockTransport(handler)


@pytest.fixture
def mocked_executor(
    scope_guard: ScopeGuard,
    session_manager: SessionManager,
    mock_juice_shop_transport: httpx.MockTransport
) -> RequestExecutor:
    """Provides a RequestExecutor wired to the MockTransport."""
    client = httpx.Client(
        transport=mock_juice_shop_transport,
        follow_redirects=False,
        timeout=httpx.Timeout(5.0)
    )
    return RequestExecutor(
        scope_guard=scope_guard,
        session_manager=session_manager,
        client=client
    )


@pytest.fixture
def in_memory_db() -> DatabaseManager:
    """Provides an isolated in-memory SQLite database manager for unit tests."""
    db_mgr = DatabaseManager(db_path=":memory:")
    db_mgr.init_schema()
    return db_mgr


@pytest.fixture
def finding_repo(in_memory_db: DatabaseManager) -> FindingRepository:
    """Provides a FindingRepository backed by an in-memory database."""
    return FindingRepository(db_manager=in_memory_db)


@pytest.fixture(autouse=True)
def reset_assessment_rate_limiter() -> None:
    """Keep test cases isolated from the process-wide production rate limiter."""
    assessment_creation_limiter.reset()
