from uuid import UUID

from app.models.enums import IncidentStatus


class ApplicationError(Exception):
    """Base exception for application business errors."""


class IncidentNotFoundError(ApplicationError):
    """Raised when an incident cannot be found."""

    def __init__(self, incident_id: UUID) -> None:
        self.incident_id = incident_id
        super().__init__(f"Incident {incident_id} was not found.")


class InvalidIncidentTransitionError(ApplicationError):
    """Raised when an incident status transition is invalid."""

    def __init__(
        self,
        current_status: IncidentStatus,
        requested_status: IncidentStatus,
    ) -> None:
        self.current_status = current_status
        self.requested_status = requested_status

        super().__init__(
            f"Cannot transition incident from "
            f"{current_status.value} to {requested_status.value}."
        )


class IncidentResolutionRequiredError(ApplicationError):
    """Raised when resolving an incident without a resolution."""

    def __init__(self) -> None:
        super().__init__("A resolution is required before resolving an incident.")
