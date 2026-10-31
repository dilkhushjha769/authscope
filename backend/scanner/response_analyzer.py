"""Response Analyzer: Evaluates HTTP status codes, error patterns, and body diffs."""

from typing import Dict, Any, Optional
from backend.scanner.request_executor import HttpResponseModel
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ResponseAnalyzer:
    """Analyzes and compares HTTP responses for authorization discrepancies."""

    @staticmethod
    def is_success_response(response: HttpResponseModel) -> bool:
        """Determines if a response indicates successful access.

        Checks that status code is 2xx and response does not contain generic error payloads.
        """
        if not (200 <= response.status_code < 300):
            return False

        # TODO (Phase 4): Add deep JSON inspection to filter false positive 200 OK errors
        if response.json_data and isinstance(response.json_data, dict):
            status_val = str(response.json_data.get("status", "")).lower()
            if status_val in ["error", "fail", "unauthorized"]:
                return False

        return True

