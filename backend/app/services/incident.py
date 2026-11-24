from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import (
    IncidentNotFoundError,
    IncidentResolutionRequiredError,
)
from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.repositories import IncidentRepository
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services.incident_lifecycle import validate_status_transition


class IncidentService:
    """Coordinate incident management and enforce business rules."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repository = IncidentRepository(session)

    def create_incident(self, data: IncidentCreate) -> Incident:
        """Create a new incident with the default open status."""
        incident = Incident(
            title=data.title,
            description=data.description,
            priority=data.priority,
            category=data.category,
            status=IncidentStatus.OPEN,
        )

        try:
            incident = self.repository.create(incident)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

        return incident

    def get_incident(self, incident_id: UUID) -> Incident:
        """Retrieve an incident or raise a business exception."""
        incident = self.repository.get_by_id(incident_id)

        if incident is None:
            raise IncidentNotFoundError(incident_id)

        return incident

    def list_incidents(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        status: IncidentStatus | None = None,
        priority: IncidentPriority | None = None,
        category: str | None = None,
    ) -> list[Incident]:
        """Retrieve incidents with pagination and filtering."""
        return self.repository.list_all(
            offset=offset,
            limit=limit,
            status=status,
            priority=priority,
            category=category,
        )

    def count_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        priority: IncidentPriority | None = None,
        category: str | None = None,
    ) -> int:
        """Count incidents matching the supplied filters."""
        return self.repository.count(
            status=status,
            priority=priority,
            category=category,
        )

    def update_incident(
        self,
        incident_id: UUID,
        data: IncidentUpdate,
    ) -> Incident:
        """Update an incident while enforcing lifecycle rules."""
        incident = self.get_incident(incident_id)
        changes = data.model_dump(exclude_unset=True)

        if not changes:
            return incident

        current_status = incident.status
        requested_status = data.status if data.status is not None else current_status

        validate_status_transition(
            current_status,
            requested_status,
        )

        resolution = changes.get(
            "resolution",
            incident.resolution,
        )

        if (
            requested_status
            in (
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
            )
            and not resolution
        ):
            raise IncidentResolutionRequiredError()

        try:
            for field, value in changes.items():
                setattr(incident, field, value)

            if requested_status != current_status:
                if requested_status == IncidentStatus.RESOLVED:
                    incident.resolved_at = datetime.now(UTC)

                elif (
                    current_status == IncidentStatus.RESOLVED
                    and requested_status == IncidentStatus.IN_PROGRESS
                ):
                    incident.resolved_at = None

            incident = self.repository.update(incident)
            self.session.commit()

        except Exception:
            self.session.rollback()
            raise

        return incident

    def delete_incident(self, incident_id: UUID) -> None:
        """Delete an existing incident."""
        incident = self.get_incident(incident_id)

        try:
            self.repository.delete(incident)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
