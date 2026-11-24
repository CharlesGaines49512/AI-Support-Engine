from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.api.ai_dependencies import (
    AIAnalysisQueryDependency,
    PersistentAIAnalysisDependency,
)
from app.core.exceptions import IncidentNotFoundError
from app.models.ai_enums import AIAnalysisStatus
from app.schemas.ai_analysis_response import AIAnalysisResponse
from app.schemas.pagination import PaginatedResponse
from app.services.ai_analysis_query import AIAnalysisNotFoundError
from app.services.persistent_ai_analysis import (
    IncidentChangedDuringAnalysisError,
)

router = APIRouter(
    prefix="/incidents/{incident_id}/analyses",
    tags=["AI Analyses"],
)


@router.post(
    "",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"description": "Incident not found"},
        409: {"description": "Incident changed during analysis"},
    },
)
async def create_analysis(
    incident_id: UUID,
    service: PersistentAIAnalysisDependency,
) -> AIAnalysisResponse:
    """Generate and persist an incident analysis attempt."""
    try:
        result = await service.analyze_incident(incident_id)

    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None

    except IncidentChangedDuringAnalysisError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from None

    return AIAnalysisResponse.model_validate(result)


@router.get(
    "",
    response_model=PaginatedResponse[AIAnalysisResponse],
    responses={
        404: {"description": "Incident not found"},
    },
)
def list_analyses(
    incident_id: UUID,
    service: AIAnalysisQueryDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    analysis_status: Annotated[
        AIAnalysisStatus | None,
        Query(alias="status"),
    ] = None,
) -> PaginatedResponse[AIAnalysisResponse]:
    """Retrieve paginated incident analysis history."""
    try:
        return service.list_analyses(
            incident_id,
            offset=offset,
            limit=limit,
            status=analysis_status,
        )

    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None


@router.get(
    "/latest",
    response_model=AIAnalysisResponse,
    responses={
        404: {"description": "Incident or analysis not found"},
    },
)
def get_latest_analysis(
    incident_id: UUID,
    service: AIAnalysisQueryDependency,
) -> AIAnalysisResponse:
    """Retrieve the most recent analysis attempt."""
    try:
        return service.get_latest(incident_id)

    except (
        IncidentNotFoundError,
        AIAnalysisNotFoundError,
    ) as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None


@router.get(
    "/latest-successful",
    response_model=AIAnalysisResponse,
    responses={
        404: {"description": "Incident or successful analysis not found"},
    },
)
def get_latest_successful_analysis(
    incident_id: UUID,
    service: AIAnalysisQueryDependency,
) -> AIAnalysisResponse:
    """Retrieve the most recent successful analysis."""
    try:
        return service.get_latest_successful(incident_id)

    except (
        IncidentNotFoundError,
        AIAnalysisNotFoundError,
    ) as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None


@router.get(
    "/{analysis_id}",
    response_model=AIAnalysisResponse,
    responses={
        404: {"description": "Incident or analysis not found"},
    },
)
def get_analysis(
    incident_id: UUID,
    analysis_id: UUID,
    service: AIAnalysisQueryDependency,
) -> AIAnalysisResponse:
    """Retrieve an individual incident analysis."""
    try:
        return service.get_analysis(
            incident_id,
            analysis_id,
        )

    except (
        IncidentNotFoundError,
        AIAnalysisNotFoundError,
    ) as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None
