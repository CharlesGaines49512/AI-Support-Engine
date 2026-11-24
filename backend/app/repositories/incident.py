from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus


class IncidentRepository:
    """Manage database operations for technical support incidents."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, incident: Incident) -> Incident:
        """Add a new incident to the database session."""
        self.session.add(incident)
        self.session.flush()
        self.session.refresh(incident)
        return incident

    def get_by_id(self, incident_id: UUID) -> Incident | None:
        """Retrieve an incident by its unique identifier."""
        return self.session.get(Incident, incident_id)

    def list_all(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        status: IncidentStatus | None = None,
        priority: IncidentPriority | None = None,
        category: str | None = None,
    ) -> list[Incident]:
        """Retrieve incidents with pagination and optional filters."""
        statement = select(Incident)

        if status is not None:
            statement = statement.where(Incident.status == status)

        if priority is not None:
            statement = statement.where(Incident.priority == priority)

        if category is not None:
            statement = statement.where(Incident.category == category)

        statement = (
            statement.order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def count(
        self,
        *,
        status: IncidentStatus | None = None,
        priority: IncidentPriority | None = None,
        category: str | None = None,
    ) -> int:
        """Count incidents matching the supplied filters."""
        statement = select(func.count()).select_from(Incident)

        if status is not None:
            statement = statement.where(Incident.status == status)

        if priority is not None:
            statement = statement.where(Incident.priority == priority)

        if category is not None:
            statement = statement.where(Incident.category == category)

        return self.session.execute(statement).scalar_one()

    def update(self, incident: Incident) -> Incident:
        """Flush changes to an existing managed incident."""
        self.session.flush()
        self.session.refresh(incident)
        return incident

    def delete(self, incident: Incident) -> None:
        """Mark an incident for deletion."""
        self.session.delete(incident)
        self.session.flush()
