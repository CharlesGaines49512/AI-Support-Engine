from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import IncidentNotFoundError
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.services.ai_metrics import AIMetricsService


@pytest.fixture
def incident_id(
    integration_session: Session,
) -> UUID:
    incident = Incident(
        id=uuid4(),
        title="Synthetic metrics incident",
        description="Database connectivity failure.",
        category="ai-metrics-integration",
    )

    integration_session.add(incident)
    integration_session.flush()

    return incident.id


def create_success(
    incident_id: UUID,
    *,
    cost: Decimal | None = None,
    latency: float = 200.0,
    include_usage: bool = True,
) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connectivity failure.",
        justification="Repeated connection timeouts.",
        confidence=0.9,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        input_tokens=1000 if include_usage else None,
        output_tokens=500 if include_usage else None,
        cached_input_tokens=400 if include_usage else None,
        total_tokens=1500 if include_usage else None,
        estimated_cost_usd=cost,
        latency_ms=latency,
        redaction_count=0,
        input_characters=3000,
    )


def create_failure(
    incident_id: UUID,
    *,
    latency: float | None = 300.0,
) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
        latency_ms=latency,
    )


def test_empty_incident_metrics(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    assert metrics.total_analyses == 0
    assert metrics.successful_analyses == 0
    assert metrics.failed_analyses == 0
    assert metrics.success_rate_percent is None
    assert metrics.average_latency_ms is None
    assert metrics.latency_sample_count == 0

    assert metrics.total_input_tokens is None
    assert metrics.total_output_tokens is None
    assert metrics.total_cached_input_tokens is None
    assert metrics.total_tokens is None

    assert metrics.input_usage_sample_count == 0
    assert metrics.output_usage_sample_count == 0
    assert metrics.cached_usage_sample_count == 0
    assert metrics.total_usage_sample_count == 0

    assert metrics.estimated_cost_usd is None
    assert metrics.costed_analyses == 0
    assert metrics.uncosted_analyses == 0


def test_aggregated_metrics(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    integration_session.add_all(
        [
            create_success(
                incident_id,
                cost=Decimal("0.0054000000"),
                latency=200.0,
            ),
            create_success(
                incident_id,
                cost=Decimal("0.0054000000"),
                latency=400.0,
            ),
            create_failure(
                incident_id,
                latency=300.0,
            ),
        ]
    )

    integration_session.flush()

    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    assert metrics.total_analyses == 3
    assert metrics.successful_analyses == 2
    assert metrics.failed_analyses == 1
    assert metrics.success_rate_percent == 66.67
    assert metrics.average_latency_ms == 300.0
    assert metrics.latency_sample_count == 3

    assert metrics.total_input_tokens == 2000
    assert metrics.total_output_tokens == 1000
    assert metrics.total_cached_input_tokens == 800
    assert metrics.total_tokens == 3000

    assert metrics.input_usage_sample_count == 2
    assert metrics.output_usage_sample_count == 2
    assert metrics.cached_usage_sample_count == 2
    assert metrics.total_usage_sample_count == 2

    assert metrics.estimated_cost_usd == Decimal("0.0108000000")

    assert metrics.costed_analyses == 2
    assert metrics.uncosted_analyses == 1


def test_unknown_usage_and_cost(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    integration_session.add(
        create_success(
            incident_id,
            include_usage=False,
        )
    )

    integration_session.flush()

    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    assert metrics.total_analyses == 1
    assert metrics.success_rate_percent == 100.0
    assert metrics.total_tokens is None
    assert metrics.total_usage_sample_count == 0
    assert metrics.estimated_cost_usd is None
    assert metrics.costed_analyses == 0
    assert metrics.uncosted_analyses == 1


def test_zero_cost_is_known_cost(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    integration_session.add(
        create_success(
            incident_id,
            cost=Decimal("0.0000000000"),
        )
    )

    integration_session.flush()

    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    assert metrics.estimated_cost_usd == Decimal("0")
    assert metrics.costed_analyses == 1
    assert metrics.uncosted_analyses == 0


def test_failed_only_metrics(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    integration_session.add(
        create_failure(
            incident_id,
            latency=None,
        )
    )

    integration_session.flush()

    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    assert metrics.total_analyses == 1
    assert metrics.successful_analyses == 0
    assert metrics.failed_analyses == 1
    assert metrics.success_rate_percent == 0.0
    assert metrics.average_latency_ms is None
    assert metrics.latency_sample_count == 0
    assert metrics.estimated_cost_usd is None


def test_metrics_incident_isolation(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    other = Incident(
        id=uuid4(),
        title="Unrelated synthetic incident",
        description="Network unavailable.",
    )

    integration_session.add(other)
    integration_session.flush()

    integration_session.add_all(
        [
            create_success(
                incident_id,
                cost=Decimal("0.0054000000"),
            ),
            create_failure(other.id),
        ]
    )

    integration_session.flush()

    service = AIMetricsService(integration_session)

    first = service.get_metrics(incident_id)
    second = service.get_metrics(other.id)

    assert first.total_analyses == 1
    assert first.successful_analyses == 1
    assert first.failed_analyses == 0

    assert second.total_analyses == 1
    assert second.successful_analyses == 0
    assert second.failed_analyses == 1
    assert second.estimated_cost_usd is None


def test_global_metrics(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    service = AIMetricsService(integration_session)

    before = service.get_metrics()

    integration_session.add(
        create_success(
            incident_id,
            cost=Decimal("0.0054000000"),
        )
    )

    integration_session.flush()

    after = service.get_metrics()

    assert after.total_analyses == (before.total_analyses + 1)

    assert after.successful_analyses == (before.successful_analyses + 1)

    assert after.failed_analyses == (before.failed_analyses)

    assert after.costed_analyses == (before.costed_analyses + 1)

    previous_cost = (
        before.estimated_cost_usd
        if before.estimated_cost_usd is not None
        else Decimal("0")
    )

    assert after.estimated_cost_usd == (previous_cost + Decimal("0.0054000000"))


def test_missing_incident_metrics(
    integration_session: Session,
) -> None:
    service = AIMetricsService(integration_session)

    with pytest.raises(IncidentNotFoundError):
        service.get_metrics(uuid4())


def test_metrics_json_serialization(
    integration_session: Session,
    incident_id: UUID,
) -> None:
    integration_session.add(
        create_success(
            incident_id,
            cost=Decimal("0.0054000000"),
        )
    )

    integration_session.flush()

    metrics = AIMetricsService(integration_session).get_metrics(incident_id)

    payload = metrics.model_dump(mode="json")

    assert payload["estimated_cost_usd"] == ("0.0054000000")

    assert payload["total_tokens"] == 1500
    assert payload["success_rate_percent"] == 100.0
    assert payload["costed_analyses"] == 1
    assert payload["uncosted_analyses"] == 0
