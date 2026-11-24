from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.repositories import AIAnalysisRepository


@pytest.fixture
def repository(
    integration_session: Session,
) -> AIAnalysisRepository:
    return AIAnalysisRepository(integration_session)


@pytest.fixture
def incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="Synthetic repository integration incident",
        description="Database connection timed out.",
        category="ai-repository-integration",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


def create_successful_analysis(
    incident_id: UUID,
    created_at: datetime,
) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connectivity failure.",
        justification="The database is unreachable.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
        created_at=created_at,
    )


def create_failed_analysis(
    incident_id: UUID,
    created_at: datetime,
) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
        created_at=created_at,
    )


@pytest.fixture
def history(
    repository: AIAnalysisRepository,
    incident: Incident,
) -> list[AIAnalysis]:
    start = datetime.now(UTC)

    records = [
        create_successful_analysis(
            incident.id,
            start,
        ),
        create_failed_analysis(
            incident.id,
            start + timedelta(seconds=1),
        ),
        create_successful_analysis(
            incident.id,
            start + timedelta(seconds=2),
        ),
        create_failed_analysis(
            incident.id,
            start + timedelta(seconds=3),
        ),
    ]

    return [repository.create(record) for record in records]


def test_create_analysis(
    repository: AIAnalysisRepository,
    incident: Incident,
) -> None:
    record = create_successful_analysis(
        incident.id,
        datetime.now(UTC),
    )

    result = repository.create(record)

    assert result.id is not None
    assert result.incident_id == incident.id
    assert result.status == AIAnalysisStatus.SUCCEEDED
    assert result.created_at.tzinfo is not None


def test_retrieve_analysis(
    integration_session: Session,
    repository: AIAnalysisRepository,
    history: list[AIAnalysis],
) -> None:
    analysis_id = history[0].id

    integration_session.expunge(history[0])

    retrieved = repository.get_by_id(analysis_id)

    assert retrieved is not None
    assert retrieved.id == analysis_id
    assert retrieved.suggested_category == "database"


def test_retrieve_missing_analysis(
    repository: AIAnalysisRepository,
) -> None:
    assert repository.get_by_id(uuid4()) is None


def test_analysis_history_ordering(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    records = repository.list_by_incident(incident.id)

    assert [record.id for record in records] == [
        record.id for record in reversed(history)
    ]


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_filter_analysis_history(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
    status: AIAnalysisStatus,
) -> None:
    records = repository.list_by_incident(
        incident.id,
        status=status,
    )

    expected = [record.id for record in reversed(history) if record.status == status]

    assert len(records) == 2
    assert [record.id for record in records] == expected


def test_paginated_analysis_history(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    first_page = repository.list_by_incident(
        incident.id,
        offset=0,
        limit=2,
    )

    second_page = repository.list_by_incident(
        incident.id,
        offset=2,
        limit=2,
    )

    assert [record.id for record in first_page] == [
        history[3].id,
        history[2].id,
    ]

    assert [record.id for record in second_page] == [
        history[1].id,
        history[0].id,
    ]

    assert not (
        {record.id for record in first_page} & {record.id for record in second_page}
    )


def test_filtered_pagination(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    records = repository.list_by_incident(
        incident.id,
        offset=1,
        limit=1,
        status=AIAnalysisStatus.SUCCEEDED,
    )

    assert [record.id for record in records] == [history[0].id]


def test_pagination_beyond_history(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    assert (
        repository.list_by_incident(
            incident.id,
            offset=len(history),
            limit=10,
        )
        == []
    )


def test_count_analysis_history(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    assert repository.count_by_incident(incident.id) == len(history)


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_count_filtered_history(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
    status: AIAnalysisStatus,
) -> None:
    expected = sum(record.status == status for record in history)

    assert (
        repository.count_by_incident(
            incident.id,
            status=status,
        )
        == expected
    )


def test_latest_analysis(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    result = repository.get_latest(incident.id)

    assert result is not None
    assert result.id == history[3].id
    assert result.status == AIAnalysisStatus.FAILED


def test_latest_successful_analysis(
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    result = repository.get_latest_successful(incident.id)

    assert result is not None
    assert result.id == history[2].id
    assert result.status == AIAnalysisStatus.SUCCEEDED


def test_empty_analysis_history(
    repository: AIAnalysisRepository,
    incident: Incident,
) -> None:
    assert repository.list_by_incident(incident.id) == []
    assert repository.count_by_incident(incident.id) == 0
    assert repository.get_latest(incident.id) is None

    assert repository.get_latest_successful(incident.id) is None


def test_failed_only_history(
    repository: AIAnalysisRepository,
    incident: Incident,
) -> None:
    failed = repository.create(
        create_failed_analysis(
            incident.id,
            datetime.now(UTC),
        )
    )

    latest = repository.get_latest(incident.id)

    assert latest is not None
    assert latest.id == failed.id

    assert repository.get_latest_successful(incident.id) is None


def test_incident_history_isolation(
    integration_session: Session,
    repository: AIAnalysisRepository,
    incident: Incident,
    history: list[AIAnalysis],
) -> None:
    other_incident = Incident(
        title="Unrelated synthetic incident",
        description="Network connectivity failure.",
        category="ai-repository-integration",
    )

    integration_session.add(other_incident)
    integration_session.flush()

    unrelated = repository.create(
        create_successful_analysis(
            other_incident.id,
            datetime.now(UTC),
        )
    )

    records = repository.list_by_incident(incident.id)

    assert len(records) == len(history)
    assert unrelated.id not in {record.id for record in records}

    assert repository.count_by_incident(other_incident.id) == 1

    assert repository.count_by_incident(incident.id) == len(history)


def test_identical_timestamp_ordering(
    repository: AIAnalysisRepository,
    incident: Incident,
) -> None:
    timestamp = datetime.now(UTC)

    first = create_successful_analysis(
        incident.id,
        timestamp,
    )

    second = create_successful_analysis(
        incident.id,
        timestamp,
    )

    first.id = UUID(int=1)
    second.id = UUID(int=2)

    repository.create(first)
    repository.create(second)

    records = repository.list_by_incident(incident.id)

    assert [record.id for record in records] == [
        second.id,
        first.id,
    ]


def test_repository_transaction_rollback(
    integration_session: Session,
    repository: AIAnalysisRepository,
    incident: Incident,
) -> None:
    transaction = integration_session.begin_nested()

    record = repository.create(
        create_successful_analysis(
            incident.id,
            datetime.now(UTC),
        )
    )

    analysis_id = record.id

    transaction.rollback()

    assert repository.get_by_id(analysis_id) is None
    assert repository.count_by_incident(incident.id) == 0

    assert (
        integration_session.get(
            Incident,
            incident.id,
        )
        is not None
    )
