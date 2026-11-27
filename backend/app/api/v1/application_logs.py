from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from starlette.concurrency import run_in_threadpool

from app.api.error_responses import (
    VALIDATION_ERROR_RESPONSES,
    http_error_response,
)
from app.api.log_dependencies import (
    LogIngestionDependency,
    LogQueryDependency,
)
from app.api.log_request_schema import JSON_LOG_REQUEST_SCHEMA
from app.api.log_requests import read_log_payload
from app.core.config import Settings, get_settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.ai_evidence_contracts import (
    AIAnalysisLogContext,
    InvalidLogEvidenceError,
)
from app.logs.exceptions import (
    LogEntryNotFoundError,
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import (
    LogParsingError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
)
from app.schemas.application_log import (
    LogEntryResponse,
    LogEvidencePackageResponse,
    LogEvidenceResponse,
    LogIngestionResponse,
    LogSubmissionResponse,
)
from app.schemas.pagination import PaginatedResponse
from app.services.log_query import (
    MAX_PAGE_OFFSET,
    MAX_PAGE_SIZE,
)

router = APIRouter(
    responses=VALIDATION_ERROR_RESPONSES,
    prefix="/incidents/{incident_id}/logs",
    tags=["Application Logs"],
)


@router.post(
    "",
    response_model=LogIngestionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: http_error_response("Invalid log request"),
        404: http_error_response("Incident not found"),
        413: http_error_response("Log resource limit exceeded"),
        415: http_error_response("Unsupported media type"),
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/xml": {
                    "schema": {"type": "string"},
                },
                "text/xml": {
                    "schema": {"type": "string"},
                },
                "application/json": {
                    "schema": JSON_LOG_REQUEST_SCHEMA,
                },
                "text/plain": {
                    "schema": {"type": "string"},
                },
            },
        },
    },
)
async def ingest_application_log(
    incident_id: UUID,
    request: Request,
    service: LogIngestionDependency,
    settings: Annotated[Settings, Depends(get_settings)],
    source_format: Annotated[
        LogFormat,
        Query(description="Declared application log format."),
    ],
    source_name: Annotated[
        str | None,
        Header(
            alias="X-Log-Source-Name",
            description=(
                "Optional application log source name. "
                "Only printable ASCII characters are supported. "
                "The configurable length limit defaults to "
                "500 characters. Percent-encoded values are "
                "not automatically decoded."
            ),
        ),
    ] = None,
) -> LogIngestionResponse:
    """Ingest, sanitize and persist an application log submission.

    Submit a nonempty, uncompressed UTF-8 request body.
    The Content-Type must match the source_format parameter:

    - xml: application/xml or text/xml.
    - json: application/json.
    - text: text/plain.

    Only one optional UTF-8 charset declaration is supported.
    Duplicate singleton headers and conflicting request framing
    are rejected. Compressed requests are not supported.

    Default configurable resource limits:

    - Payload: 1,048,576 bytes (1 MiB).
    - Entries: 1,000.
    - Nesting depth: 32.
    - Message and exception fields: 10,000 characters.
    - Metadata fields: 500 characters.

    Deployment configuration may change these limits.
    JSON logs reject duplicate keys, unsupported fields,
    numeric values and Boolean field values. Each JSON entry
    requires a nonempty message after whitespace trimming.

    Submitted log content is validated and sanitized before
    persistence. Invalid or unsafe content is rejected.
    """

    if source_name is not None and any(
        not 32 <= ord(character) <= 126 for character in source_name
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("Log source name must contain only printable ASCII characters."),
        )

    if source_name is not None and len(source_name) > settings.log_max_metadata_chars:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Log source name exceeds the configured length limit.",
        )

    payload = await read_log_payload(
        request,
        source_format,
        settings.log_max_payload_bytes,
    )

    try:
        result = await run_in_threadpool(
            service.ingest,
            incident_id,
            payload,
            source_format,
            source_name=source_name,
        )

    except IncidentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident was not found.",
        ) from None

    except (
        LogPayloadTooLargeError,
        LogResourceLimitError,
    ):
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Log submission exceeds a configured resource limit.",
        ) from None

    except LogParsingError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log submission contains invalid or unsupported content.",
        ) from None

    return LogIngestionResponse.model_validate(result)


@router.get(
    "",
    response_model=PaginatedResponse[LogSubmissionResponse],
    responses={
        404: http_error_response("Incident not found"),
        409: http_error_response("Stored application log content is invalid"),
    },
)
def list_log_submissions(
    incident_id: UUID,
    service: LogQueryDependency,
    offset: Annotated[
        int,
        Query(ge=0, le=MAX_PAGE_OFFSET),
    ] = 0,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_PAGE_SIZE),
    ] = 20,
) -> PaginatedResponse[LogSubmissionResponse]:
    """Retrieve paginated application log submissions."""

    try:
        page = service.list_submissions(
            incident_id,
            offset=offset,
            limit=limit,
        )

    except IncidentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident was not found.",
        ) from None
    except LogPersistenceIntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored application log content could not be verified.",
        ) from None

    return PaginatedResponse[LogSubmissionResponse](
        items=[LogSubmissionResponse.model_validate(item) for item in page.items],
        total=page.total,
        offset=page.offset,
        limit=page.limit,
        has_more=page.has_more,
    )


@router.get(
    "/{submission_id}",
    response_model=LogSubmissionResponse,
    responses={
        404: http_error_response("Incident or log submission not found"),
        409: http_error_response("Stored application log content is invalid"),
    },
)
def get_log_submission(
    incident_id: UUID,
    submission_id: UUID,
    service: LogQueryDependency,
) -> LogSubmissionResponse:
    """Retrieve an incident-scoped application log submission."""

    try:
        result = service.get_submission(
            incident_id,
            submission_id,
        )

    except (
        IncidentNotFoundError,
        LogSubmissionNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log submission was not found.",
        ) from None
    except LogPersistenceIntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored application log content could not be verified.",
        ) from None

    return LogSubmissionResponse.model_validate(result)


@router.get(
    "/{submission_id}/entries",
    response_model=PaginatedResponse[LogEntryResponse],
    responses={
        404: http_error_response("Incident or log submission not found"),
        409: http_error_response("Stored application log content is invalid"),
    },
)
def list_log_entries(
    incident_id: UUID,
    submission_id: UUID,
    service: LogQueryDependency,
    offset: Annotated[
        int,
        Query(ge=0, le=MAX_PAGE_OFFSET),
    ] = 0,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_PAGE_SIZE),
    ] = 20,
    severity: LogSeverity | None = None,
) -> PaginatedResponse[LogEntryResponse]:
    """Retrieve sanitized application log entries."""

    try:
        page = service.list_entries(
            incident_id,
            submission_id,
            offset=offset,
            limit=limit,
            severity=severity,
        )

    except (
        IncidentNotFoundError,
        LogSubmissionNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log submission was not found.",
        ) from None
    except LogPersistenceIntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored application log content could not be verified.",
        ) from None

    return PaginatedResponse[LogEntryResponse](
        items=[LogEntryResponse.model_validate(item) for item in page.items],
        total=page.total,
        offset=page.offset,
        limit=page.limit,
        has_more=page.has_more,
    )


@router.get(
    "/{submission_id}/entries/{entry_id}",
    response_model=LogEntryResponse,
    responses={
        404: http_error_response("Incident, submission or log entry not found"),
        409: http_error_response("Stored application log content is invalid"),
    },
)
def get_log_entry(
    incident_id: UUID,
    submission_id: UUID,
    entry_id: UUID,
    service: LogQueryDependency,
) -> LogEntryResponse:
    """Retrieve an individual sanitized application log entry."""

    try:
        result = service.get_entry(
            incident_id,
            submission_id,
            entry_id,
        )

    except (
        IncidentNotFoundError,
        LogSubmissionNotFoundError,
        LogEntryNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log entry was not found.",
        ) from None
    except LogPersistenceIntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored application log content could not be verified.",
        ) from None

    return LogEntryResponse.model_validate(result)


@router.get(
    "/{submission_id}/evidence",
    response_model=LogEvidenceResponse,
    responses={
        404: http_error_response("Incident or log submission not found"),
        409: http_error_response("Stored diagnostic evidence is invalid"),
    },
)
def get_log_evidence(
    incident_id: UUID,
    submission_id: UUID,
    service: LogQueryDependency,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LogEvidenceResponse:
    """Retrieve validated, incident-scoped diagnostic evidence."""

    try:
        evidence = service.get_evidence(
            incident_id,
            submission_id,
        )

        context = AIAnalysisLogContext(
            incident_id=incident_id,
            submission_id=submission_id,
            evidence=evidence,
        )

        context.validate(
            settings,
            incident_id,
        )

    except (
        IncidentNotFoundError,
        LogSubmissionNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log submission was not found.",
        ) from None

    except (
        InvalidLogEvidenceError,
        LogPersistenceIntegrityError,
        LogParsingError,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored diagnostic evidence could not be verified.",
        ) from None

    return LogEvidenceResponse(
        incident_id=incident_id,
        submission_id=submission_id,
        evidence=LogEvidencePackageResponse.model_validate(evidence),
    )


@router.delete(
    "/{submission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={
        404: http_error_response("Incident or log submission not found"),
    },
)
def delete_log_submission(
    incident_id: UUID,
    submission_id: UUID,
    service: LogQueryDependency,
) -> Response:
    """Delete an incident-scoped application log submission."""

    try:
        service.delete_submission(
            incident_id,
            submission_id,
        )

    except (
        IncidentNotFoundError,
        LogSubmissionNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application log submission was not found.",
        ) from None

    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
    )
