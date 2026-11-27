from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.api.ai_dependencies import (
    AIAnalysisQueryDependency,
    PersistentAIAnalysisDependency,
)
from app.api.ai_requests import BoundedAIRequestRoute
from app.api.error_responses import (
    VALIDATION_ERROR_RESPONSES,
    http_error_response,
)
from app.core.exceptions import IncidentNotFoundError
from app.logs.ai_evidence_contracts import InvalidLogEvidenceError
from app.logs.exceptions import (
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.models.ai_enums import AIAnalysisStatus
from app.parsers.exceptions import LogParsingError
from app.schemas.ai_analysis_request import AIAnalysisRequest
from app.schemas.ai_analysis_response import AIAnalysisResponse
from app.schemas.pagination import PaginatedResponse
from app.services.ai_analysis_query import AIAnalysisNotFoundError
from app.services.persistent_ai_analysis import (
    IncidentChangedDuringAnalysisError,
    LogEvidenceChangedDuringAnalysisError,
)

router = APIRouter(
    responses=VALIDATION_ERROR_RESPONSES,
    prefix="/incidents/{incident_id}/analyses",
    tags=["AI Analyses"],
    route_class=BoundedAIRequestRoute,
)


@router.post(
    "",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: http_error_response("Incident or log submission not found"),
        409: http_error_response("Incident or diagnostic evidence conflict"),
        400: http_error_response("Invalid or ambiguous AI request"),
        413: http_error_response("AI request size limit exceeded"),
        415: http_error_response("Unsupported AI request media type"),
    },
)
async def create_analysis(
    incident_id: UUID,
    service: PersistentAIAnalysisDependency,
    data: AIAnalysisRequest | None = None,
) -> AIAnalysisResponse:
    """Generate and persist a standard or log-enhanced analysis.

    Omit the request body, submit null, submit an empty JSON
    object, or set log_submission_id to null for standard
    incident analysis.

    Provide log_submission_id as a UUID to request log-enhanced
    analysis. The submission must belong to the same incident.

    When Content-Type is supplied, it must be application/json
    with at most one optional UTF-8 charset declaration.
    Requests must be uncompressed UTF-8 content.

    Fixed request resource limits:

    - Request body: 4,096 bytes.
    - JSON nesting depth: 32.

    Duplicate JSON keys, unsupported JSON constants, duplicate
    singleton headers and conflicting request framing are rejected.
    Unknown request properties are not supported.

    Log-enhanced analysis requires validated diagnostic evidence.
    Invalid or changed evidence may result in HTTP 409.
    """

    try:
        if data is None or data.log_submission_id is None:
            result = await service.analyze_incident(incident_id)
        else:
            result = await service.analyze_incident(
                incident_id,
                submission_id=data.log_submission_id,
            )

    except IncidentNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from None

    except LogSubmissionNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log submission was not found.",
        ) from None

    except IncidentChangedDuringAnalysisError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from None

    except LogEvidenceChangedDuringAnalysisError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Diagnostic evidence changed during analysis.",
        ) from None

    except (
        InvalidLogEvidenceError,
        LogPersistenceIntegrityError,
        LogParsingError,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Diagnostic evidence could not be verified.",
        ) from None

    return AIAnalysisResponse.model_validate(result)


@router.get(
    "",
    response_model=PaginatedResponse[AIAnalysisResponse],
    responses={
        404: http_error_response("Incident not found"),
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
        404: http_error_response("Incident or analysis not found"),
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
        404: http_error_response("Incident or successful analysis not found"),
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
        404: http_error_response("Incident or analysis not found"),
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
