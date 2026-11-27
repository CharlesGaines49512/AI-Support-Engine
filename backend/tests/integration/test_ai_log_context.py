from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.ai_evidence_contracts import (
    AIAnalysisLogContext,
    InvalidLogEvidenceError,
)
from app.logs.exceptions import LogSubmissionNotFoundError
from app.models.incident import Incident
from app.models.log_enums import LogFormat
from app.services.ai_log_context import AILogContextService
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_entries": 100,
            "log_max_evidence_entries": 20,
            "log_max_evidence_chars": 8000,
        }
    )


@pytest.fixture
def factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=True,
    )


@pytest.fixture
def incident_ids(
    factory: sessionmaker[Session],
) -> Iterator[tuple[UUID, UUID]]:
    identifiers = (uuid4(), uuid4())

    try:
        with factory.begin() as session:
            session.add_all(
                [
                    Incident(
                        id=identifier,
                        title="ai-log-context-test",
                        description="Synthetic AI evidence integration test.",
                    )
                    for identifier in identifiers
                ]
            )

        yield identifiers

    finally:
        with factory.begin() as session:
            session.execute(delete(Incident).where(Incident.id.in_(identifiers)))


@pytest.fixture
def ingestion(
    factory: sessionmaker[Session],
    settings: Settings,
) -> LogIngestionService:
    return LogIngestionService(factory, settings)


@pytest.fixture
def query(
    factory: sessionmaker[Session],
    settings: Settings,
) -> LogQueryService:
    return LogQueryService(factory, settings)


@pytest.fixture
def context_service(
    query: LogQueryService,
    settings: Settings,
) -> AILogContextService:
    return AILogContextService(query, settings)


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<event severity="ERROR" message="Database connection failed"/>',
        ),
        (
            LogFormat.JSON,
            b'{"severity":"ERROR","message":"Database connection failed"}',
        ),
        (
            LogFormat.TEXT,
            b"ERROR Database connection failed",
        ),
    ],
)
def test_context_from_persisted_log(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
    source_format: LogFormat,
    payload: bytes,
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        payload,
        source_format,
    )

    context = context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    assert isinstance(context, AIAnalysisLogContext)
    assert context.incident_id == identifier
    assert context.submission_id == submitted.submission_id

    assert context.evidence == submitted.evidence
    assert context.has_evidence is True
    assert context.selected_event_count == 1

    assert context.evidence.events[0].rule_ids == (
        "DB-002",
        "SEV-001",
    )


def test_missing_incident_rejected(
    context_service: AILogContextService,
) -> None:
    with pytest.raises(IncidentNotFoundError):
        context_service.build_context(
            uuid4(),
            uuid4(),
        )


def test_missing_submission_rejected(
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        context_service.build_context(
            incident_ids[0],
            uuid4(),
        )


def test_cross_incident_context_rejected(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    submitted = ingestion.ingest(
        incident_ids[0],
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    with pytest.raises(LogSubmissionNotFoundError):
        context_service.build_context(
            incident_ids[1],
            submitted.submission_id,
        )


def test_clean_log_context(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"INFO Application ready",
        LogFormat.TEXT,
    )

    context = context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    assert context.has_evidence is False
    assert context.selected_event_count == 0

    assert context.evidence.total_events == 1
    assert context.evidence.diagnostic_events == 0


def test_deleted_submission_rejected(
    ingestion: LogIngestionService,
    query: LogQueryService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    query.delete_submission(
        identifier,
        submitted.submission_id,
    )

    with pytest.raises(LogSubmissionNotFoundError):
        context_service.build_context(
            identifier,
            submitted.submission_id,
        )


def test_context_excludes_recognized_credentials(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"ERROR Authentication failed password=SYNTHETIC_AI_SECRET_CANARY",
        LogFormat.TEXT,
        source_name="password=SYNTHETIC_AI_SECRET_CANARY",
    )

    context = context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    serialized = context.to_json()

    assert submitted.redaction_count > 0
    assert "SYNTHETIC_AI_SECRET_CANARY" not in serialized

    assert "AUTH-001" in serialized

    assert "source_name" not in context.to_dict()


def test_context_preserves_submission_isolation(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    first = ingestion.ingest(
        identifier,
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    second = ingestion.ingest(
        identifier,
        b"CRITICAL Invalid signature",
        LogFormat.TEXT,
    )

    first_context = context_service.build_context(
        identifier,
        first.submission_id,
    )

    second_context = context_service.build_context(
        identifier,
        second.submission_id,
    )

    assert "DB-002" in first_context.to_json()
    assert "SEC-001" not in first_context.to_json()

    assert "SEC-001" in second_context.to_json()
    assert "DB-002" not in second_context.to_json()


def test_context_build_is_deterministic(
    ingestion: LogIngestionService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"ERROR Database connection failed\nCRITICAL Invalid signature",
        LogFormat.TEXT,
    )

    first = context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    second = context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    assert first == second
    assert first.to_json() == second.to_json()


def test_context_revalidates_configured_limits(
    ingestion: LogIngestionService,
    query: LogQueryService,
    settings: Settings,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"ERROR Database connection failed\nCRITICAL Invalid signature",
        LogFormat.TEXT,
    )

    limited = settings.model_copy(update={"log_max_evidence_entries": 1})

    service = AILogContextService(query, limited)

    with pytest.raises(
        InvalidLogEvidenceError,
        match="evidence entry limit",
    ):
        service.build_context(
            identifier,
            submitted.submission_id,
        )


def test_context_does_not_modify_stored_submission(
    ingestion: LogIngestionService,
    query: LogQueryService,
    context_service: AILogContextService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    submitted = ingestion.ingest(
        identifier,
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    before = query.get_submission(
        identifier,
        submitted.submission_id,
    )

    context_service.build_context(
        identifier,
        submitted.submission_id,
    )

    after = query.get_submission(
        identifier,
        submitted.submission_id,
    )

    assert before == after
    assert query.list_submissions(identifier).total == 1
