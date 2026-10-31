"""Target Manager: Tracks target base URLs, endpoints, and health status."""

from typing import Optional
from pydantic import BaseModel, HttpUrl
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class TargetMetadata(BaseModel):
    """Metadata regarding an authorized target instance."""
    base_url: str
    name: str = "OWASP Juice Shop"
    is_reachable: bool = False
    open_api_url: Optional[str] = None


class TargetManager:
    """Manages target configurations and coordinates baseline connectivity checks."""

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url.rstrip("/")
        self.metadata = TargetMetadata(base_url=self.base_url)

    def check_health(self) -> bool:
        """Verifies if the target application is reachable and responding.

        TODO (Phase 2): Implement automated ping check using RequestExecutor.
        """
        logger.info("Target health check scheduled", extra={"base_url": self.base_url})
        return self.metadata.is_reachable

