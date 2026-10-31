"""Assessment Lifecycle Management and State Transition Validation.

Defines canonical assessment lifecycle states and enforces strict state machine
transitions to prevent invalid states, race conditions, and accidental restarts.
"""

from enum import Enum
from typing import Dict, Set


class AssessmentStatus(str, Enum):
    """Canonical lifecycle states for AuthScope security assessments."""
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    # Legacy alias support for backward compatibility with existing storage
    PENDING = "PENDING"


# Strict state machine defining permitted target states from each source state
PERMITTED_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    AssessmentStatus.CREATED.value: {
        AssessmentStatus.QUEUED.value,
        AssessmentStatus.RUNNING.value,
        AssessmentStatus.CANCELLED.value,
        AssessmentStatus.FAILED.value,
    },
    AssessmentStatus.QUEUED.value: {
        AssessmentStatus.RUNNING.value,
        AssessmentStatus.CANCELLED.value,
        AssessmentStatus.FAILED.value,
    },
    AssessmentStatus.PENDING.value: {
        AssessmentStatus.RUNNING.value,
        AssessmentStatus.QUEUED.value,
        AssessmentStatus.CANCELLED.value,
        AssessmentStatus.FAILED.value,
    },
    AssessmentStatus.RUNNING.value: {
        AssessmentStatus.COMPLETED.value,
        AssessmentStatus.FAILED.value,
        AssessmentStatus.CANCELLED.value,
    },
    # Terminal states cannot transition to other states directly
    AssessmentStatus.COMPLETED.value: set(),
    AssessmentStatus.FAILED.value: set(),
    AssessmentStatus.CANCELLED.value: set(),
}


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle state transition is attempted."""
    def __init__(self, current_state: str, target_state: str, message: str = ""):
        self.current_state = current_state
        self.target_state = target_state
        self.message = (
            message
            or f"Invalid state transition: Cannot transition assessment from '{current_state}' to '{target_state}'. "
            f"Terminal states cannot be restarted directly; invoke the /retry endpoint to launch a fresh execution."
        )
        super().__init__(self.message)


def validate_state_transition(current_state: str, target_state: str) -> bool:
    """Verifies whether a lifecycle state transition is legal according to the state machine.

    Args:
        current_state: Current status string of the scan session.
        target_state: Proposed new status string.

    Returns:
        True if the transition is allowed.

    Raises:
        InvalidStateTransitionError: If the transition violates the state machine.
    """
    curr = current_state.upper()
    target = target_state.upper()

    # Self-transitions are idempotent and always permitted
    if curr == target:
        return True

    allowed_targets = PERMITTED_STATE_TRANSITIONS.get(curr, set())
    if target not in allowed_targets:
        raise InvalidStateTransitionError(current_state=curr, target_state=target)

    return True


def is_terminal_state(state: str) -> bool:
    """Returns True if the given state is a terminal, immutable state."""
    return state.upper() in (
        AssessmentStatus.COMPLETED.value,
        AssessmentStatus.FAILED.value,
        AssessmentStatus.CANCELLED.value,
    )


def is_active_state(state: str) -> bool:
    """Returns True if the assessment is actively running or queued."""
    return state.upper() in (
        AssessmentStatus.CREATED.value,
        AssessmentStatus.QUEUED.value,
        AssessmentStatus.PENDING.value,
        AssessmentStatus.RUNNING.value,
    )

