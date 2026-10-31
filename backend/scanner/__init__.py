"""Scanner package exports, loaded lazily to avoid analysis/scanner import cycles."""

from importlib import import_module
from typing import Any

__all__ = [
    "SecurityInspector",
    "DetectionCategory",
    "FindingSeverity",
    "FindingValidationStatus",
    "ParsedCookie",
    "SecurityFindingRecord",
    "CategoryInspectionResult",
]


def __getattr__(name: str) -> Any:
    """Resolve public inspection symbols only when callers request them."""
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module("backend.scanner.security_inspector")
    return getattr(module, name)
