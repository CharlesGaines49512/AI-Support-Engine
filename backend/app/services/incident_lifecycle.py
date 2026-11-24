from typing import Final

from app.core.exceptions import InvalidIncidentTransitionError
from app.models.enums import IncidentStatus

ALLOWED_TRANSITIONS: Final[dict[IncidentStatus, frozenset[IncidentStatus]]] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.IN_PROGRESS,
        }
    ),
    IncidentStatus.IN_PROGRESS: frozenset(
        {
            IncidentStatus.PENDING,
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.PENDING: frozenset(
        {
            IncidentStatus.IN_PROGRESS,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(
        {
            IncidentStatus.IN_PROGRESS,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.CLOSED: frozenset(),
}


def validate_status_transition(
    current_status: IncidentStatus,
    requested_status: IncidentStatus,
) -> None:
    """Ensure the requested incident status transition is permitted."""
    if current_status == requested_status:
        return

    if requested_status not in ALLOWED_TRANSITIONS[current_status]:
        raise InvalidIncidentTransitionError(
            current_status,
            requested_status,
        )
