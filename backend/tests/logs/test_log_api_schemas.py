from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.logs.extraction_contracts import (
    EvidenceEvent,
    EvidencePackage,
)
from app.logs.ingestion_contracts import LogIngestionResult
from app.logs.query_contracts import (
    LogEntryRecord,
    LogSubmissionRecord,
)
from app.models.log_enums import LogFormat, LogSeverity
from app.schemas.ai_analysis_request import AIAnalysisRequest
from app.schemas.application_log import (
    LogEntryResponse,
    LogEvidenceEventResponse,
    LogEvidencePackageResponse,
    LogEvidenceResponse,
    LogIngestionResponse,
    LogSubmissionResponse,
)
from app.schemas.pagination import PaginatedResponse


@pytest.fixture
def submission() -> LogSubmissionRecord:
    return LogSubmissionRecord(
        id=uuid4(),
        incident_id=uuid4(),
        source_format=LogFormat.TEXT,
        source_name="synthetic-application.log",
        payload_bytes=128,
        entry_count=3,
        redaction_count=2,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def entry(
    submission: LogSubmissionRecord,
) -> LogEntryRecord:
    return LogEntryRecord(
        id=uuid4(),
        submission_id=submission.id,
        position=2,
        severity=LogSeverity.ERROR,
        message="Database connection failed.",
        event_timestamp=datetime.now(UTC),
        original_severity="ERROR",
        service_name="database-service",
        exception="Synthetic database exception.",
        error_code="DB-CONNECTION",
        correlation_id="synthetic-correlation-id",
    )


@pytest.fixture
def event() -> EvidenceEvent:
    return EvidenceEvent(
        position=2,
        severity=LogSeverity.ERROR,
        score=65,
        rule_ids=("DB-002",),
        categories=("database",),
        message="Database connection failed.",
        service_name="database-service",
    )


@pytest.fixture
def evidence(
    event: EvidenceEvent,
) -> EvidencePackage:
    return EvidencePackage(
        source_format=LogFormat.TEXT,
        total_events=3,
        diagnostic_events=2,
        events=(event,),
    )


def test_submission_record_serialization(
    submission: LogSubmissionRecord,
) -> None:
    response = LogSubmissionResponse.model_validate(submission)

    assert response.id == submission.id
    assert response.incident_id == submission.incident_id
    assert response.source_format == LogFormat.TEXT
    assert response.source_name == submission.source_name
    assert response.payload_bytes == 128
    assert response.entry_count == 3
    assert response.redaction_count == 2
    assert response.created_at == submission.created_at

    data = response.model_dump(mode="json")

    assert data["id"] == str(submission.id)
    assert data["source_format"] == "text"


def test_submission_excludes_raw_payload(
    submission: LogSubmissionRecord,
) -> None:
    data = LogSubmissionResponse.model_validate(submission).model_dump()

    assert set(data) == {
        "id",
        "incident_id",
        "source_format",
        "source_name",
        "payload_bytes",
        "entry_count",
        "redaction_count",
        "created_at",
    }


def test_nullable_source_name(
    submission: LogSubmissionRecord,
) -> None:
    response = LogSubmissionResponse.model_validate(
        replace(submission, source_name=None)
    )

    assert response.source_name is None


@pytest.mark.parametrize(
    "source_format",
    list(LogFormat),
)
def test_supported_source_formats(
    submission: LogSubmissionRecord,
    source_format: LogFormat,
) -> None:
    response = LogSubmissionResponse.model_validate(
        replace(
            submission,
            source_format=source_format,
        )
    )

    assert response.source_format == source_format


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload_bytes", 0),
        ("payload_bytes", -1),
        ("payload_bytes", 10485761),
        ("entry_count", 0),
        ("entry_count", 10001),
        ("redaction_count", -1),
        ("source_name", "A" * 2001),
        ("source_format", "unsupported"),
        ("id", "invalid-uuid"),
        ("incident_id", "invalid-uuid"),
    ],
)
def test_invalid_submission_metadata_rejected(
    submission: LogSubmissionRecord,
    field: str,
    value: object,
) -> None:
    data = LogSubmissionResponse.model_validate(submission).model_dump()

    data[field] = value

    with pytest.raises(ValidationError):
        LogSubmissionResponse.model_validate(data)


def test_entry_record_serialization(
    entry: LogEntryRecord,
) -> None:
    response = LogEntryResponse.model_validate(entry)

    assert response.id == entry.id
    assert response.submission_id == entry.submission_id
    assert response.position == 2
    assert response.severity == LogSeverity.ERROR
    assert response.message == entry.message
    assert response.event_timestamp == entry.event_timestamp
    assert response.service_name == entry.service_name
    assert response.exception == entry.exception
    assert response.original_severity == entry.original_severity
    assert response.error_code == entry.error_code
    assert response.correlation_id == entry.correlation_id


@pytest.mark.parametrize(
    "severity",
    list(LogSeverity),
)
def test_supported_log_severities(
    entry: LogEntryRecord,
    severity: LogSeverity,
) -> None:
    response = LogEntryResponse.model_validate(replace(entry, severity=severity))

    assert response.severity == severity


def test_entry_optional_fields(
    submission: LogSubmissionRecord,
) -> None:
    record = LogEntryRecord(
        id=uuid4(),
        submission_id=submission.id,
        position=1,
        severity=LogSeverity.UNKNOWN,
        message="Synthetic application event.",
    )

    response = LogEntryResponse.model_validate(record)

    assert response.event_timestamp is None
    assert response.original_severity is None
    assert response.service_name is None
    assert response.exception is None
    assert response.error_code is None
    assert response.correlation_id is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("position", 0),
        ("position", -1),
        ("position", 10001),
        ("severity", "invalid"),
        ("message", ""),
        ("message", "A" * 20001),
        ("exception", "A" * 20001),
        ("original_severity", "A" * 2001),
        ("service_name", "A" * 2001),
        ("error_code", "A" * 2001),
        ("correlation_id", "A" * 2001),
    ],
)
def test_invalid_entry_metadata_rejected(
    entry: LogEntryRecord,
    field: str,
    value: object,
) -> None:
    data = LogEntryResponse.model_validate(entry).model_dump()

    data[field] = value

    with pytest.raises(ValidationError):
        LogEntryResponse.model_validate(data)


def test_evidence_event_serialization(
    event: EvidenceEvent,
) -> None:
    response = LogEvidenceEventResponse.model_validate(event)

    assert response.position == 2
    assert response.severity == LogSeverity.ERROR
    assert response.score == 65
    assert response.rule_ids == ("DB-002",)
    assert response.categories == ("database",)
    assert response.details_omitted is False
    assert response.message == event.message

    data = response.model_dump(mode="json")

    assert data["rule_ids"] == ["DB-002"]
    assert data["categories"] == ["database"]


def test_evidence_excludes_unselected_metadata(
    event: EvidenceEvent,
) -> None:
    data = LogEvidenceEventResponse.model_validate(event).model_dump()

    assert "correlation_id" not in data
    assert "original_severity" not in data
    assert "raw_payload" not in data


def test_metadata_only_evidence(
    event: EvidenceEvent,
) -> None:
    response = LogEvidenceEventResponse.model_validate(
        replace(
            event,
            details_omitted=True,
            message=None,
            service_name=None,
        )
    )

    assert response.details_omitted is True
    assert response.message is None
    assert response.service_name is None
    assert response.rule_ids == ("DB-002",)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("position", 0),
        ("score", -1),
        ("score", 111),
        ("rule_ids", ()),
        ("categories", ()),
        ("message", "A" * 20001),
        ("exception", "A" * 20001),
        ("service_name", "A" * 2001),
        ("error_code", "A" * 2001),
        ("event_timestamp", "A" * 2001),
    ],
)
def test_invalid_evidence_event_rejected(
    event: EvidenceEvent,
    field: str,
    value: object,
) -> None:
    data = LogEvidenceEventResponse.model_validate(event).model_dump()

    data[field] = value

    with pytest.raises(ValidationError):
        LogEvidenceEventResponse.model_validate(data)


def test_evidence_package_serialization(
    evidence: EvidencePackage,
) -> None:
    response = LogEvidencePackageResponse.model_validate(evidence)

    assert response.source_format == LogFormat.TEXT
    assert response.total_events == 3
    assert response.diagnostic_events == 2
    assert response.selected_event_count == 1
    assert response.omitted_event_count == 1
    assert response.has_evidence is True
    assert len(response.events) == 1


def test_empty_diagnostic_evidence() -> None:
    package = EvidencePackage(
        source_format=LogFormat.JSON,
        total_events=1,
        diagnostic_events=0,
        events=(),
    )

    response = LogEvidencePackageResponse.model_validate(package)

    assert response.selected_event_count == 0
    assert response.omitted_event_count == 0
    assert response.has_evidence is False
    assert response.events == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_events", 0),
        ("total_events", 10001),
        ("diagnostic_events", -1),
        ("diagnostic_events", 10001),
        ("selected_event_count", -1),
        ("selected_event_count", 101),
        ("omitted_event_count", -1),
        ("omitted_event_count", 10001),
    ],
)
def test_invalid_evidence_accounting_rejected(
    evidence: EvidencePackage,
    field: str,
    value: object,
) -> None:
    data = LogEvidencePackageResponse.model_validate(evidence).model_dump()

    data[field] = value

    with pytest.raises(ValidationError):
        LogEvidencePackageResponse.model_validate(data)


def test_scoped_evidence_response(
    submission: LogSubmissionRecord,
    evidence: EvidencePackage,
) -> None:
    response = LogEvidenceResponse(
        incident_id=submission.incident_id,
        submission_id=submission.id,
        evidence=LogEvidencePackageResponse.model_validate(evidence),
    )

    data = response.model_dump(mode="json")

    assert data["schema_version"] == "1.0.0"
    assert data["trust_level"] == "untrusted"
    assert data["evidence_type"] == "diagnostic_indicators"
    assert data["incident_id"] == str(submission.incident_id)
    assert data["submission_id"] == str(submission.id)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "invalid"),
        ("trust_level", "trusted"),
        ("evidence_type", "confirmed_root_cause"),
    ],
)
def test_invalid_evidence_trust_metadata_rejected(
    submission: LogSubmissionRecord,
    evidence: EvidencePackage,
    field: str,
    value: str,
) -> None:
    data = LogEvidenceResponse(
        incident_id=submission.incident_id,
        submission_id=submission.id,
        evidence=LogEvidencePackageResponse.model_validate(evidence),
    ).model_dump()

    data[field] = value

    with pytest.raises(ValidationError):
        LogEvidenceResponse.model_validate(data)


def test_ingestion_result_serialization(
    submission: LogSubmissionRecord,
    evidence: EvidencePackage,
) -> None:
    result = LogIngestionResult(
        submission_id=submission.id,
        incident_id=submission.incident_id,
        source_format=submission.source_format,
        source_name=submission.source_name,
        payload_bytes=submission.payload_bytes,
        entry_count=submission.entry_count,
        redaction_count=submission.redaction_count,
        created_at=submission.created_at,
        evidence=evidence,
    )

    response = LogIngestionResponse.model_validate(result)

    assert response.submission_id == submission.id
    assert response.incident_id == submission.incident_id
    assert response.entry_count == 3
    assert response.redaction_count == 2
    assert response.was_redacted is True
    assert response.has_diagnostic_evidence is True
    assert response.evidence.selected_event_count == 1


def test_ingestion_result_without_redaction_or_evidence(
    submission: LogSubmissionRecord,
) -> None:
    result = LogIngestionResult(
        submission_id=submission.id,
        incident_id=submission.incident_id,
        source_format=LogFormat.TEXT,
        source_name=None,
        payload_bytes=32,
        entry_count=1,
        redaction_count=0,
        created_at=submission.created_at,
        evidence=EvidencePackage(
            source_format=LogFormat.TEXT,
            total_events=1,
            diagnostic_events=0,
            events=(),
        ),
    )

    response = LogIngestionResponse.model_validate(result)

    assert response.was_redacted is False
    assert response.has_diagnostic_evidence is False


def test_submission_pagination(
    submission: LogSubmissionRecord,
) -> None:
    response = PaginatedResponse[LogSubmissionResponse](
        items=[LogSubmissionResponse.model_validate(submission)],
        total=2,
        offset=0,
        limit=1,
        has_more=True,
    )

    data = response.model_dump(mode="json")

    assert data["total"] == 2
    assert data["has_more"] is True
    assert data["items"][0]["id"] == str(submission.id)


def test_entry_pagination(
    entry: LogEntryRecord,
) -> None:
    response = PaginatedResponse[LogEntryResponse](
        items=[LogEntryResponse.model_validate(entry)],
        total=1,
        offset=0,
        limit=20,
        has_more=False,
    )

    assert response.total == 1
    assert response.has_more is False
    assert response.items[0].id == entry.id


def test_empty_submission_pagination() -> None:
    response = PaginatedResponse[LogSubmissionResponse](
        items=[],
        total=0,
        offset=0,
        limit=20,
        has_more=False,
    )

    assert response.items == []
    assert response.total == 0


def test_legacy_analysis_request() -> None:
    response = AIAnalysisRequest()

    assert response.log_submission_id is None


def test_enhanced_analysis_request() -> None:
    identifier = uuid4()

    response = AIAnalysisRequest(
        log_submission_id=identifier,
    )

    assert response.log_submission_id == identifier


def test_analysis_request_uuid_deserialization() -> None:
    identifier = uuid4()

    response = AIAnalysisRequest.model_validate({"log_submission_id": str(identifier)})

    assert isinstance(response.log_submission_id, UUID)
    assert response.log_submission_id == identifier


def test_explicit_null_analysis_request() -> None:
    response = AIAnalysisRequest.model_validate({"log_submission_id": None})

    assert response.log_submission_id is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "invalid-uuid",
        123,
        [],
        {},
    ],
)
def test_invalid_analysis_identifier_rejected(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        AIAnalysisRequest.model_validate({"log_submission_id": value})


@pytest.mark.parametrize(
    "field",
    [
        "incident_id",
        "provider",
        "model",
        "system_prompt",
        "user_prompt",
        "raw_payload",
        "api_key",
        "evidence",
        "confidence",
        "priority",
    ],
)
def test_analysis_request_rejects_unknown_fields(
    field: str,
) -> None:
    with pytest.raises(ValidationError):
        AIAnalysisRequest.model_validate({field: "synthetic-value"})


def test_analysis_request_is_immutable() -> None:
    request = AIAnalysisRequest()

    with pytest.raises(ValidationError):
        type(request).__setattr__(
            request,
            "log_submission_id",
            uuid4(),
        )


def test_submission_schema_rejects_raw_payload(
    submission: LogSubmissionRecord,
) -> None:
    data = LogSubmissionResponse.model_validate(submission).model_dump()

    data["raw_payload"] = "Synthetic raw log content."

    with pytest.raises(ValidationError):
        LogSubmissionResponse.model_validate(data)


def test_evidence_schema_rejects_system_prompt(
    evidence: EvidencePackage,
) -> None:
    data = LogEvidencePackageResponse.model_validate(evidence).model_dump()

    data["system_prompt"] = "Synthetic unauthorized instruction."

    with pytest.raises(ValidationError):
        LogEvidencePackageResponse.model_validate(data)
