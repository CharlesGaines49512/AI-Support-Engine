from typing import cast
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, Table, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.models.application_log import LogSubmission
from app.models.log_enums import LogFormat
from app.repositories.ai_analysis import AIAnalysisRepository
from app.schemas.ai_analysis_response import AIAnalysisResponse

DIGEST = "a" * 64
VERSION = "1.0.0"


@pytest.fixture
def incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="AI provenance integration test",
        description="Synthetic evidence attribution.",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


@pytest.fixture
def submission(
    integration_session: Session,
    incident: Incident,
) -> LogSubmission:
    record = LogSubmission(
        incident_id=incident.id,
        source_format=LogFormat.TEXT,
        payload_bytes=100,
        entry_count=1,
        redaction_count=0,
    )

    integration_session.add(record)
    integration_session.flush()

    return record


def make_analysis(
    incident_id: UUID,
    *,
    submission_id: UUID | None = None,
    version: str | None = None,
    digest: str | None = None,
    event_count: int | None = None,
) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Synthetic database failure.",
        justification="Database connectivity requires investigation.",
        confidence=0.8,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version=("1.1.0" if submission_id is not None else "1.0.0"),
        latency_ms=100.0,
        redaction_count=0,
        input_characters=3000,
        log_submission_id=submission_id,
        log_evidence_version=version,
        log_evidence_sha256=digest,
        log_evidence_event_count=event_count,
    )


@pytest.mark.parametrize(
    "column",
    [
        "log_submission_id",
        "log_evidence_version",
        "log_evidence_sha256",
        "log_evidence_event_count",
    ],
)
def test_provenance_columns_exist(
    column: str,
) -> None:
    field = AIAnalysis.__table__.columns[column]

    assert field.nullable is True


def test_provenance_constraint_registered() -> None:
    names = {
        constraint.name
        for constraint in cast(Table, AIAnalysis.__table__).constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert "ck_ai_analyses_log_evidence_consistency" in names


def test_provenance_index_registered() -> None:
    names = {index.name for index in cast(Table, AIAnalysis.__table__).indexes}

    assert "ix_ai_analyses_log_submission_id" in names


def test_historical_reference_is_not_foreign_key() -> None:
    column = AIAnalysis.__table__.columns["log_submission_id"]

    assert not column.foreign_keys


def test_legacy_analysis_still_supported(
    integration_session: Session,
    incident: Incident,
) -> None:
    analysis = AIAnalysisRepository(integration_session).create(
        make_analysis(incident.id)
    )

    assert analysis.log_submission_id is None
    assert analysis.log_evidence_version is None
    assert analysis.log_evidence_sha256 is None
    assert analysis.log_evidence_event_count is None

    response = AIAnalysisResponse.model_validate(analysis)

    assert response.log_submission_id is None
    assert response.log_evidence_version is None
    assert response.log_evidence_sha256 is None
    assert response.log_evidence_event_count is None


@pytest.mark.parametrize(
    "event_count",
    [0, 1, 20, 100],
)
def test_complete_provenance_persisted(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
    event_count: int,
) -> None:
    analysis = AIAnalysisRepository(integration_session).create(
        make_analysis(
            incident.id,
            submission_id=submission.id,
            version=VERSION,
            digest=DIGEST,
            event_count=event_count,
        )
    )

    analysis_id = analysis.id

    integration_session.expire_all()

    stored = integration_session.get(
        AIAnalysis,
        analysis_id,
    )

    assert stored is not None
    assert stored.log_submission_id == submission.id
    assert stored.log_evidence_version == VERSION
    assert stored.log_evidence_sha256 == DIGEST
    assert stored.log_evidence_event_count == event_count


@pytest.mark.parametrize(
    "missing_field",
    [
        "submission_id",
        "version",
        "digest",
        "event_count",
    ],
)
def test_partial_provenance_rejected(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
    missing_field: str,
) -> None:
    analysis = make_analysis(
        incident.id,
        submission_id=(None if missing_field == "submission_id" else submission.id),
        version=(None if missing_field == "version" else VERSION),
        digest=(None if missing_field == "digest" else DIGEST),
        event_count=(None if missing_field == "event_count" else 1),
    )

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            integration_session.add(analysis)
            integration_session.flush()


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "a" * 63,
        "g" * 64,
        "A" * 64,
        " " * 64,
    ],
)
def test_invalid_digest_rejected(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
    digest: str,
) -> None:
    analysis = make_analysis(
        incident.id,
        submission_id=submission.id,
        version=VERSION,
        digest=digest,
        event_count=1,
    )

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            integration_session.add(analysis)
            integration_session.flush()


@pytest.mark.parametrize("version", ["", " ", "   "])
def test_empty_version_rejected(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
    version: str,
) -> None:
    analysis = make_analysis(
        incident.id,
        submission_id=submission.id,
        version=version,
        digest=DIGEST,
        event_count=1,
    )

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            integration_session.add(analysis)
            integration_session.flush()


@pytest.mark.parametrize("event_count", [-1, 101, 1000])
def test_invalid_event_count_rejected(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
    event_count: int,
) -> None:
    analysis = make_analysis(
        incident.id,
        submission_id=submission.id,
        version=VERSION,
        digest=DIGEST,
        event_count=event_count,
    )

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            integration_session.add(analysis)
            integration_session.flush()


def test_failed_analysis_supports_provenance(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
) -> None:
    analysis = AIAnalysis(
        incident_id=incident.id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.1.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
        log_submission_id=submission.id,
        log_evidence_version=VERSION,
        log_evidence_sha256=DIGEST,
        log_evidence_event_count=1,
    )

    stored = AIAnalysisRepository(integration_session).create(analysis)

    assert stored.status == AIAnalysisStatus.FAILED
    assert stored.log_submission_id == submission.id
    assert stored.log_evidence_sha256 == DIGEST


def test_response_serializes_provenance(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
) -> None:
    analysis = AIAnalysisRepository(integration_session).create(
        make_analysis(
            incident.id,
            submission_id=submission.id,
            version=VERSION,
            digest=DIGEST,
            event_count=1,
        )
    )

    response = AIAnalysisResponse.model_validate(analysis)
    document = response.model_dump(mode="json")

    assert document["log_submission_id"] == str(submission.id)

    assert document["log_evidence_version"] == VERSION
    assert document["log_evidence_sha256"] == DIGEST
    assert document["log_evidence_event_count"] == 1


def test_submission_deletion_preserves_history(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
) -> None:
    analysis = AIAnalysisRepository(integration_session).create(
        make_analysis(
            incident.id,
            submission_id=submission.id,
            version=VERSION,
            digest=DIGEST,
            event_count=1,
        )
    )

    analysis_id = analysis.id
    submission_id = submission.id

    integration_session.delete(submission)
    integration_session.flush()
    integration_session.expire_all()

    stored = integration_session.get(
        AIAnalysis,
        analysis_id,
    )

    assert stored is not None
    assert stored.log_submission_id == submission_id
    assert stored.log_evidence_sha256 == DIGEST

    assert (
        integration_session.get(
            LogSubmission,
            submission_id,
        )
        is None
    )


def test_incident_deletion_removes_analysis(
    integration_session: Session,
    incident: Incident,
    submission: LogSubmission,
) -> None:
    analysis = AIAnalysisRepository(integration_session).create(
        make_analysis(
            incident.id,
            submission_id=submission.id,
            version=VERSION,
            digest=DIGEST,
            event_count=1,
        )
    )

    analysis_id = analysis.id
    submission_id = submission.id

    integration_session.delete(incident)
    integration_session.flush()
    integration_session.expunge_all()

    assert (
        integration_session.get(
            AIAnalysis,
            analysis_id,
        )
        is None
    )

    assert (
        integration_session.get(
            LogSubmission,
            submission_id,
        )
        is None
    )


def test_database_provenance_index_exists(
    integration_session: Session,
) -> None:
    inspector = inspect(integration_session.connection())

    indexes = {index["name"] for index in inspector.get_indexes("ai_analyses")}

    assert "ix_ai_analyses_log_submission_id" in indexes


def test_database_provenance_constraint_exists(
    integration_session: Session,
) -> None:
    inspector = inspect(integration_session.connection())

    constraints = {
        constraint["name"]
        for constraint in inspector.get_check_constraints("ai_analyses")
    }

    assert "ck_ai_analyses_log_evidence_consistency" in constraints
