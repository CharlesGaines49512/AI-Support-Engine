from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus
from app.repositories import AIAnalysisRepository


@pytest.fixture
def session() -> MagicMock:
    return MagicMock(spec=Session)


@pytest.fixture
def repository(
    session: MagicMock,
) -> AIAnalysisRepository:
    return AIAnalysisRepository(session)


@pytest.fixture
def analysis() -> AIAnalysis:
    return AIAnalysis(
        id=uuid4(),
        incident_id=uuid4(),
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
    )


def test_repository_initialization(
    repository: AIAnalysisRepository,
) -> None:
    assert isinstance(repository, AIAnalysisRepository)


def test_create_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    result = repository.create(analysis)

    assert result is analysis

    session.add.assert_called_once_with(analysis)
    session.flush.assert_called_once_with()
    session.refresh.assert_called_once_with(analysis)
    session.commit.assert_not_called()


def test_get_analysis_by_id(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    session.get.return_value = analysis

    result = repository.get_by_id(analysis.id)

    assert result is analysis

    session.get.assert_called_once_with(
        AIAnalysis,
        analysis.id,
    )


def test_get_missing_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.get.return_value = None

    assert repository.get_by_id(uuid4()) is None


def test_list_incident_analyses(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    session.scalars.return_value.all.return_value = [analysis]

    result = repository.list_by_incident(analysis.incident_id)

    assert result == [analysis]

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile()

    assert "ai_analyses.incident_id" in str(compiled)
    assert analysis.incident_id in compiled.params.values()
    assert "ORDER BY" in str(compiled)
    assert "ai_analyses.created_at DESC" in str(compiled)
    assert "ai_analyses.id DESC" in str(compiled)


def test_list_empty_analysis_history(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.scalars.return_value.all.return_value = []

    assert repository.list_by_incident(uuid4()) == []


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_filter_analysis_history(
    repository: AIAnalysisRepository,
    session: MagicMock,
    status: AIAnalysisStatus,
) -> None:
    session.scalars.return_value.all.return_value = []

    repository.list_by_incident(
        uuid4(),
        status=status,
    )

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile()

    assert "ai_analyses.status =" in str(compiled)
    assert status in compiled.params.values()


def test_analysis_pagination(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.scalars.return_value.all.return_value = []

    repository.list_by_incident(
        uuid4(),
        offset=20,
        limit=10,
    )

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile()

    assert "LIMIT" in str(compiled)
    assert "OFFSET" in str(compiled)
    assert 10 in compiled.params.values()
    assert 20 in compiled.params.values()


def test_count_incident_analyses(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    incident_id = uuid4()

    session.execute.return_value.scalar_one.return_value = 5

    assert repository.count_by_incident(incident_id) == 5

    statement = session.execute.call_args.args[0]
    compiled = statement.compile()

    assert "count(" in str(compiled).lower()
    assert incident_id in compiled.params.values()


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_count_filtered_analyses(
    repository: AIAnalysisRepository,
    session: MagicMock,
    status: AIAnalysisStatus,
) -> None:
    session.execute.return_value.scalar_one.return_value = 2

    result = repository.count_by_incident(
        uuid4(),
        status=status,
    )

    assert result == 2

    statement = session.execute.call_args.args[0]
    compiled = statement.compile()

    assert "ai_analyses.status =" in str(compiled)
    assert status in compiled.params.values()


def test_count_empty_analysis_history(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.execute.return_value.scalar_one.return_value = 0

    assert repository.count_by_incident(uuid4()) == 0


def test_get_latest_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    session.scalars.return_value.all.return_value = [analysis]

    result = repository.get_latest(analysis.incident_id)

    assert result is analysis

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile()

    assert 1 in compiled.params.values()


def test_get_latest_missing_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.scalars.return_value.all.return_value = []

    assert repository.get_latest(uuid4()) is None


def test_get_latest_successful_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    session.scalars.return_value.all.return_value = [analysis]

    result = repository.get_latest_successful(analysis.incident_id)

    assert result is analysis

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile()

    assert AIAnalysisStatus.SUCCEEDED in (compiled.params.values())
    assert 1 in compiled.params.values()


def test_get_latest_successful_missing_analysis(
    repository: AIAnalysisRepository,
    session: MagicMock,
) -> None:
    session.scalars.return_value.all.return_value = []

    assert repository.get_latest_successful(uuid4()) is None


def test_repository_does_not_commit_transactions(
    repository: AIAnalysisRepository,
    session: MagicMock,
    analysis: AIAnalysis,
) -> None:
    session.scalars.return_value.all.return_value = []
    session.execute.return_value.scalar_one.return_value = 0

    repository.create(analysis)
    repository.get_by_id(analysis.id)
    repository.list_by_incident(analysis.incident_id)
    repository.count_by_incident(analysis.incident_id)
    repository.get_latest(analysis.incident_id)
    repository.get_latest_successful(analysis.incident_id)

    session.commit.assert_not_called()
    session.rollback.assert_not_called()
    session.close.assert_not_called()
