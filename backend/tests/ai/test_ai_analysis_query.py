from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import IncidentNotFoundError
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.services.ai_analysis_query import (
    AIAnalysisNotFoundError,
    AIAnalysisQueryService,
)


@pytest.fixture
def incident() -> Incident:
    return Incident(
        id=uuid4(),
        title="Synthetic incident",
        description="Database connection failed.",
    )


@pytest.fixture
def analysis(incident: Incident) -> AIAnalysis:
    return AIAnalysis(
        id=uuid4(),
        incident_id=incident.id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connection failure.",
        justification="Repeated connection timeouts.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def session(
    incident: Incident,
    analysis: AIAnalysis,
) -> MagicMock:
    result = MagicMock(spec=Session)

    result.get.side_effect = [
        incident,
        analysis,
    ]

    result.scalars.return_value.all.return_value = [analysis]

    result.execute.return_value.scalar_one.return_value = 1

    return result


@pytest.fixture
def service(
    session: MagicMock,
) -> AIAnalysisQueryService:
    return AIAnalysisQueryService(session)


def test_get_analysis(
    service: AIAnalysisQueryService,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    response = service.get_analysis(
        incident.id,
        analysis.id,
    )

    assert response.id == analysis.id
    assert response.incident_id == incident.id
    assert response.status == AIAnalysisStatus.SUCCEEDED


def test_missing_incident(
    service: AIAnalysisQueryService,
    session: MagicMock,
) -> None:
    session.get.side_effect = None
    session.get.return_value = None

    incident_id = uuid4()

    with pytest.raises(IncidentNotFoundError):
        service.get_analysis(
            incident_id,
            uuid4(),
        )

    session.get.assert_called_once_with(
        Incident,
        incident_id,
    )


def test_missing_analysis(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.get.side_effect = [incident, None]

    with pytest.raises(AIAnalysisNotFoundError):
        service.get_analysis(
            incident.id,
            uuid4(),
        )


def test_analysis_incident_isolation(
    service: AIAnalysisQueryService,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    analysis.incident_id = uuid4()

    with pytest.raises(AIAnalysisNotFoundError):
        service.get_analysis(
            incident.id,
            analysis.id,
        )


def test_list_analysis_history(
    service: AIAnalysisQueryService,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    response = service.list_analyses(incident.id)

    assert len(response.items) == 1
    assert response.items[0].id == analysis.id
    assert response.total == 1
    assert response.offset == 0
    assert response.limit == 20
    assert response.has_more is False


def test_empty_analysis_history(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.scalars.return_value.all.return_value = []
    session.execute.return_value.scalar_one.return_value = 0

    response = service.list_analyses(incident.id)

    assert response.items == []
    assert response.total == 0
    assert response.has_more is False


def test_analysis_pagination(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.execute.return_value.scalar_one.return_value = 10

    response = service.list_analyses(
        incident.id,
        offset=2,
        limit=1,
    )

    assert len(response.items) == 1
    assert response.total == 10
    assert response.offset == 2
    assert response.limit == 1
    assert response.has_more is True


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_status_filter(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
    status: AIAnalysisStatus,
) -> None:
    session.scalars.return_value.all.return_value = []
    session.execute.return_value.scalar_one.return_value = 0

    service.list_analyses(
        incident.id,
        status=status,
    )

    list_statement = session.scalars.call_args.args[0]
    count_statement = session.execute.call_args.args[0]

    assert status in (list_statement.compile().params.values())

    assert status in (count_statement.compile().params.values())


@pytest.mark.parametrize(
    ("offset", "limit"),
    [
        (-1, 20),
        (0, 0),
        (0, -1),
        (0, 101),
    ],
)
def test_invalid_pagination(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
    offset: int,
    limit: int,
) -> None:
    with pytest.raises(ValueError):
        service.list_analyses(
            incident.id,
            offset=offset,
            limit=limit,
        )

    session.get.assert_not_called()
    session.scalars.assert_not_called()


def test_get_latest(
    service: AIAnalysisQueryService,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    response = service.get_latest(incident.id)

    assert response.id == analysis.id


def test_get_latest_missing(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.scalars.return_value.all.return_value = []

    with pytest.raises(AIAnalysisNotFoundError):
        service.get_latest(incident.id)


def test_get_latest_successful(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    response = service.get_latest_successful(incident.id)

    assert response.id == analysis.id
    assert response.status == AIAnalysisStatus.SUCCEEDED

    statement = session.scalars.call_args.args[0]

    assert AIAnalysisStatus.SUCCEEDED in (statement.compile().params.values())


def test_get_latest_successful_missing(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.scalars.return_value.all.return_value = []

    with pytest.raises(AIAnalysisNotFoundError):
        service.get_latest_successful(incident.id)


@pytest.mark.parametrize(
    "operation",
    [
        "list_analyses",
        "get_latest",
        "get_latest_successful",
    ],
)
def test_missing_incident_history(
    service: AIAnalysisQueryService,
    session: MagicMock,
    operation: str,
) -> None:
    session.get.side_effect = None
    session.get.return_value = None

    with pytest.raises(IncidentNotFoundError):
        getattr(service, operation)(uuid4())

    session.scalars.assert_not_called()
    session.execute.assert_not_called()


def test_query_service_is_read_only(
    service: AIAnalysisQueryService,
    session: MagicMock,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    session.get.side_effect = [
        incident,
        analysis,
        incident,
        incident,
        incident,
    ]

    service.get_analysis(
        incident.id,
        analysis.id,
    )

    service.list_analyses(incident.id)
    service.get_latest(incident.id)
    service.get_latest_successful(incident.id)

    session.add.assert_not_called()
    session.delete.assert_not_called()
    session.flush.assert_not_called()
    session.commit.assert_not_called()
    session.rollback.assert_not_called()
    session.close.assert_not_called()
