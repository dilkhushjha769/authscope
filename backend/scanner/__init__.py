"""Scanner package public interface.

Keep scanner submodules lazy: evidence validation imports request execution,
and eagerly loading the security inspector here would create a circular import.
"""

from importlib import import_module
from typing import Any

_PUBLIC_TYPES = {
    "CategoryInspectionResult",
    "DetectionCategory",
    "FindingSeverity",
    "FindingValidationStatus",
    "ParsedCookie",
    "SecurityFindingRecord",
    "SecurityInspector",
}

__all__ = sorted(_PUBLIC_TYPES)


def __getattr__(name: str) -> Any:
    """Load security inspection types only when callers request them."""
    if name not in _PUBLIC_TYPES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module = import_module("backend.scanner.security_inspector")
    value = getattr(module, name)
    globals()[name] = value
    return value
