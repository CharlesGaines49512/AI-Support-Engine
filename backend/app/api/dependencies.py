from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services import IncidentService

DatabaseSession = Annotated[Session, Depends(get_db)]


def get_incident_service(
    session: DatabaseSession,
) -> IncidentService:
    """Provide an incident service for the current request."""
    return IncidentService(session)


IncidentServiceDependency = Annotated[
    IncidentService,
    Depends(get_incident_service),
]
