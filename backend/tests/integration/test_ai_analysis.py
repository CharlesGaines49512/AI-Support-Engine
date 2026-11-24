from decimal import Decimal
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus


@pytest.fixture
def incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="Synthetic AI integration incident",
        description="Database connection failed.",
        category="ai-integration-test",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


@pytest.fixture
def analysis(incident: Incident) -> AIAnalysis:
    return AIAnalysis(
        incident_id=incident.id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connection failure.",
        justification="The database is unreachable.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        request_id="req_integration_test",
        input_tokens=1000,
        output_tokens=200,
        total_tokens=1200,
        cached_input_tokens=100,
        estimated_cost_usd=Decimal("0.0015000000"),
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
    )


def test_successful_analysis_persistence(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    integration_session.add(analysis)
    integration_session.flush()

    analysis_id = analysis.id

    integration_session.expunge(analysis)

    retrieved = integration_session.get(
        AIAnalysis,
        analysis_id,
    )

    assert retrieved is not None
    assert retrieved.status == AIAnalysisStatus.SUCCEEDED
    assert retrieved.suggested_category == "database"
    assert retrieved.recommended_priority == "high"
    assert retrieved.recommended_severity == "high"
    assert retrieved.confidence == 0.90
    assert retrieved.created_at.tzinfo is not None


def test_failed_analysis_persistence(
    integration_session: Session,
    incident: Incident,
) -> None:
    record = AIAnalysis(
        incident_id=incident.id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
    )

    integration_session.add(record)
    integration_session.flush()
    integration_session.refresh(record)

    assert record.status == AIAnalysisStatus.FAILED
    assert record.error_code == "provider_timeout"
    assert record.summary is None
    assert record.missing_information is None
    assert record.total_tokens is None
    assert record.estimated_cost_usd is None


def test_analysis_history(
    integration_session: Session,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    failed = AIAnalysis(
        incident_id=incident.id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
    )

    integration_session.add_all([analysis, failed])
    integration_session.flush()

    records = integration_session.scalars(
        select(AIAnalysis).where(AIAnalysis.incident_id == incident.id)
    ).all()

    assert len(records) == 2

    assert {record.status for record in records} == {
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    }


def test_missing_information_persistence(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    analysis.insufficient_evidence = True
    analysis.missing_information = [
        "Database error code",
        "Number of affected users",
    ]

    integration_session.add(analysis)
    integration_session.flush()

    analysis_id = analysis.id
    integration_session.expunge(analysis)

    retrieved = integration_session.get(
        AIAnalysis,
        analysis_id,
    )

    assert retrieved is not None
    assert retrieved.insufficient_evidence is True
    assert retrieved.missing_information == [
        "Database error code",
        "Number of affected users",
    ]


def test_cost_precision(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    analysis.estimated_cost_usd = Decimal("0.0000123456")

    integration_session.add(analysis)
    integration_session.flush()

    analysis_id = analysis.id
    integration_session.expunge(analysis)

    retrieved = integration_session.get(
        AIAnalysis,
        analysis_id,
    )

    assert retrieved is not None
    assert retrieved.estimated_cost_usd == Decimal("0.0000123456")


def test_unknown_priority_persistence(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    analysis.recommended_priority = None
    analysis.insufficient_evidence = True
    analysis.missing_information = ["Business impact"]

    integration_session.add(analysis)
    integration_session.flush()
    integration_session.refresh(analysis)

    assert analysis.recommended_priority is None
    assert analysis.insufficient_evidence is True


def test_unknown_usage_remains_null(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    analysis.input_tokens = None
    analysis.output_tokens = None
    analysis.total_tokens = None
    analysis.cached_input_tokens = None
    analysis.estimated_cost_usd = None

    integration_session.add(analysis)
    integration_session.flush()
    integration_session.refresh(analysis)

    assert analysis.input_tokens is None
    assert analysis.output_tokens is None
    assert analysis.total_tokens is None
    assert analysis.cached_input_tokens is None
    assert analysis.estimated_cost_usd is None


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        ("confidence", -0.01, "confidence_range"),
        ("confidence", 1.01, "confidence_range"),
        ("confidence", float("nan"), "confidence_range"),
        ("input_tokens", -1, "input_tokens_nonnegative"),
        ("output_tokens", -1, "output_tokens_nonnegative"),
        ("total_tokens", -1, "total_tokens_nonnegative"),
        (
            "cached_input_tokens",
            -1,
            "cached_tokens_nonnegative",
        ),
        (
            "cached_input_tokens",
            1001,
            "cached_tokens_range",
        ),
        ("total_tokens", 999, "token_total_consistency"),
        ("latency_ms", -1, "latency_range"),
        ("latency_ms", float("inf"), "latency_range"),
        ("latency_ms", float("nan"), "latency_range"),
        (
            "estimated_cost_usd",
            Decimal("-0.01"),
            "cost_range",
        ),
        (
            "estimated_cost_usd",
            Decimal("NaN"),
            "cost_range",
        ),
        (
            "redaction_count",
            -1,
            "redaction_count_nonnegative",
        ),
        (
            "input_characters",
            0,
            "input_characters_positive",
        ),
        (
            "missing_information",
            {"invalid": True},
            "missing_information_array",
        ),
        (
            "summary",
            None,
            "execution_status_consistency",
        ),
        (
            "error_code",
            "unexpected_error",
            "execution_status_consistency",
        ),
    ],
)
def test_database_constraint_enforcement(
    integration_session: Session,
    analysis: AIAnalysis,
    field: str,
    value: object,
    constraint: str,
) -> None:
    # Isolate each invalid insert in a savepoint.
    with pytest.raises(IntegrityError) as error:
        with integration_session.begin_nested():
            setattr(analysis, field, value)

            # Avoid overlapping token constraints when
            # testing individual nonnegative requirements.
            if field == "input_tokens" and value == -1:
                analysis.cached_input_tokens = None
                analysis.total_tokens = None

            if field == "output_tokens" and value == -1:
                analysis.total_tokens = None

            if field == "total_tokens" and value == -1:
                analysis.input_tokens = None
                analysis.output_tokens = None

            integration_session.add(analysis)
            integration_session.flush()

    diagnostic = getattr(error.value.orig, "diag", None)

    assert getattr(diagnostic, "constraint_name", None) == (
        f"ck_ai_analyses_{constraint}"
    )


def test_failed_analysis_requires_error_details(
    integration_session: Session,
    incident: Incident,
) -> None:
    record = AIAnalysis(
        incident_id=incident.id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
    )

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            integration_session.add(record)
            integration_session.flush()


def test_foreign_key_enforcement(
    integration_session: Session,
    analysis: AIAnalysis,
) -> None:
    analysis.incident_id = uuid4()

    with pytest.raises(IntegrityError) as error:
        with integration_session.begin_nested():
            integration_session.add(analysis)
            integration_session.flush()

    diagnostic = getattr(error.value.orig, "diag", None)

    assert getattr(diagnostic, "constraint_name", None) == (
        "fk_ai_analyses_incident_id_incidents"
    )


def test_transaction_rollback(
    integration_session: Session,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    transaction = integration_session.begin_nested()

    integration_session.add(analysis)
    integration_session.flush()

    analysis_id = analysis.id

    transaction.rollback()

    assert (
        integration_session.get(
            AIAnalysis,
            analysis_id,
        )
        is None
    )

    assert (
        integration_session.get(
            Incident,
            incident.id,
        )
        is not None
    )


def test_incident_cascade_deletion(
    integration_session: Session,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    integration_session.add(analysis)
    integration_session.flush()

    incident_id = incident.id

    integration_session.delete(incident)
    integration_session.flush()

    count = integration_session.scalar(
        select(func.count())
        .select_from(AIAnalysis)
        .where(AIAnalysis.incident_id == incident_id)
    )

    assert count == 0


def test_analysis_does_not_modify_incident(
    integration_session: Session,
    incident: Incident,
    analysis: AIAnalysis,
) -> None:
    original_priority = incident.priority
    original_category = incident.category
    original_status = incident.status
    original_description = incident.description

    integration_session.add(analysis)
    integration_session.flush()
    integration_session.refresh(incident)

    assert incident.priority == original_priority
    assert incident.category == original_category
    assert incident.status == original_status
    assert incident.description == original_description
