from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.api.dependencies import IncidentServiceDependency
from app.api.error_responses import (
    VALIDATION_ERROR_RESPONSES,
    http_error_response,
)
from app.core.exceptions import (
    IncidentNotFoundError,
    IncidentResolutionRequiredError,
    InvalidIncidentTransitionError,
)
from app.models.enums import IncidentPriority, IncidentStatus
from app.schemas.incident import (
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
)
from app.schemas.pagination import PaginatedResponse

router = APIRouter(
    responses=VALIDATION_ERROR_RESPONSES,
    prefix="/incidents",
    tags=["Incidents"],
)


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    data: IncidentCreate,
    service: IncidentServiceDependency,
) -> IncidentResponse:
    """Create a new technical support incident."""
    incident = service.create_incident(data)
    return IncidentResponse.model_validate(incident)


@router.get(
    "",
    response_model=PaginatedResponse[IncidentResponse],
)
def list_incidents(
    service: IncidentServiceDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    incident_status: Annotated[
        IncidentStatus | None,
        Query(alias="status"),
    ] = None,
    priority: IncidentPriority | None = None,
    category: Annotated[
        str | None,
        Query(min_length=1, max_length=100),
    ] = None,
) -> PaginatedResponse[IncidentResponse]:
    """List incidents with optional filters and pagination."""
    incidents = service.list_incidents(
        offset=offset,
        limit=limit,
        status=incident_status,
        priority=priority,
        category=category,
    )

    total = service.count_incidents(
        status=incident_status,
        priority=priority,
        category=category,
    )

    return PaginatedResponse[IncidentResponse](
        items=[IncidentResponse.model_validate(incident) for incident in incidents],
        total=total,
        offset=offset,
        limit=limit,
        has_more=offset + len(incidents) < total,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    responses={404: http_error_response("Incident not found")},
)
def get_incident(
    incident_id: UUID,
    service: IncidentServiceDependency,
) -> IncidentResponse:
    """Retrieve an incident by its unique identifier."""
    try:
        incident = service.get_incident(incident_id)
    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    return IncidentResponse.model_validate(incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    responses={
        404: http_error_response("Incident not found"),
        409: http_error_response("Incident lifecycle conflict"),
    },
)
def update_incident(
    incident_id: UUID,
    data: IncidentUpdate,
    service: IncidentServiceDependency,
) -> IncidentResponse:
    """Update an incident while enforcing lifecycle rules."""
    try:
        incident = service.update_incident(incident_id, data)
    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error
    except (
        InvalidIncidentTransitionError,
        IncidentResolutionRequiredError,
    ) as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    return IncidentResponse.model_validate(incident)


@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={404: http_error_response("Incident not found")},
)
def delete_incident(
    incident_id: UUID,
    service: IncidentServiceDependency,
) -> Response:
    """Delete an existing incident."""
    try:
        service.delete_incident(incident_id)
    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    return Response(status_code=status.HTTP_204_NO_CONTENT)
