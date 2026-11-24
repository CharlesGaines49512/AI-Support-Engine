import pytest

from app.core.exceptions import InvalidIncidentTransitionError
from app.models.enums import IncidentStatus
from app.services.incident_lifecycle import validate_status_transition

VALID_TRANSITIONS = {
    (IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS),
    (IncidentStatus.IN_PROGRESS, IncidentStatus.PENDING),
    (IncidentStatus.IN_PROGRESS, IncidentStatus.RESOLVED),
    (IncidentStatus.PENDING, IncidentStatus.IN_PROGRESS),
    (IncidentStatus.RESOLVED, IncidentStatus.IN_PROGRESS),
    (IncidentStatus.RESOLVED, IncidentStatus.CLOSED),
}


@pytest.mark.parametrize("current_status", list(IncidentStatus))
@pytest.mark.parametrize("requested_status", list(IncidentStatus))
def test_status_transition(
    current_status: IncidentStatus,
    requested_status: IncidentStatus,
) -> None:
    """Verify every possible incident status combination."""
    if (
        current_status == requested_status
        or (current_status, requested_status) in VALID_TRANSITIONS
    ):
        validate_status_transition(current_status, requested_status)
    else:
        with pytest.raises(InvalidIncidentTransitionError) as error:
            validate_status_transition(
                current_status,
                requested_status,
            )

        assert error.value.current_status == current_status
        assert error.value.requested_status == requested_status
