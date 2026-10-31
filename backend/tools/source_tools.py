"""Source Analysis Tools for AuthScope Tool Registry.

Exposes source-code location mapping, AST handler correlation, and snippet
authenticity validation backed by CodeMapper.
"""

from pathlib import Path
from typing import Optional

from backend.analysis.code_mapper import (
    CodeMapper,
    MappingStatus,
    SourceLocation,
)
from backend.tools.schemas import (
    AnalyzeSourceCodeInput,
    AnalyzeSourceCodeOutput,
    MapEndpointToCodeInput,
    MapEndpointToCodeOutput,
    SourceLocationSummary,
    ToolExecutionContext,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class SourceTools:
    """Provides source code mapping and static analysis tools backed by CodeMapper."""

    def __init__(
        self,
        mapper: Optional[CodeMapper] = None,
        repo_root: Optional[Path] = None,
        repository_name: str = "authscope"
    ):
        self.mapper = mapper or CodeMapper(
            repo_root=repo_root or Path.cwd(),
            repository_name=repository_name
        )

    def map_endpoint_to_code(
        self,
        payload: MapEndpointToCodeInput,
        context: Optional[ToolExecutionContext] = None
    ) -> MapEndpointToCodeOutput:
        """Correlates a runtime endpoint to its backend source code handler."""
        finding_stub = {
            "id": f"tool_query_{payload.endpoint}",
            "endpoint": payload.endpoint,
            "http_method": payload.http_method
        }

        result = self.mapper.map_finding(finding_stub)

        loc_summary = None
        if result.location:
            loc_summary = SourceLocationSummary(
                repository_name=result.location.repository_name,
                file_path=result.location.file_path,
                function_name=result.location.function_name,
                start_line=result.location.start_line,
                end_line=result.location.end_line,
                code_snippet=result.location.code_snippet,
                route_handler=result.location.route_handler,
                database_operation=result.location.database_operation,
                authorization_check=result.location.authorization_check,
                confidence=result.location.confidence.value if hasattr(result.location.confidence, "value") else str(result.location.confidence)
            )

        return MapEndpointToCodeOutput(
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            verified=result.verified,
            message=result.message,
            location=loc_summary,
            candidate_count=len(result.candidates)
        )

    def analyze_source_code(
        self,
        payload: AnalyzeSourceCodeInput,
        context: Optional[ToolExecutionContext] = None
    ) -> AnalyzeSourceCodeOutput:
        """Verifies a static source location, checking line numbers, function, and snippet against disk."""
        static_hint = {
            "file_path": payload.file_path,
            "start_line": payload.start_line,
            "end_line": payload.end_line,
            "function_name": payload.function_name,
            "code_snippet": payload.expected_snippet
        }

        finding_stub = {"id": "tool_verify_static"}
        result = self.mapper.map_finding(finding_stub, static_hint=static_hint)

        if result.status == MappingStatus.EXACT and result.location:
            return AnalyzeSourceCodeOutput(
                verified=True,
                status=result.status.value,
                file_path=result.location.file_path,
                actual_snippet=result.location.code_snippet,
                database_operation=result.location.database_operation,
                authorization_check=result.location.authorization_check,
                error=None
            )
        else:
            return AnalyzeSourceCodeOutput(
                verified=False,
                status=result.status.value if hasattr(result.status, "value") else str(result.status),
                file_path=payload.file_path,
                actual_snippet=None,
                database_operation=None,
                authorization_check=None,
                error=result.message
            )
