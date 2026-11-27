from decimal import Decimal
from uuid import uuid4

import pytest
from sqlalchemy import CheckConstraint, Numeric
from sqlalchemy.dialects.postgresql import JSONB

from app.core.base import Base
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus


def test_analysis_table_registration() -> None:
    assert AIAnalysis.__tablename__ == "ai_analyses"
    assert "ai_analyses" in Base.metadata.tables


def test_shared_metadata() -> None:
    assert AIAnalysis.metadata is Incident.metadata
    assert AIAnalysis.metadata is Base.metadata


def test_analysis_columns() -> None:
    expected = {
        "cached_input_tokens",
        "confidence",
        "created_at",
        "error_code",
        "error_message",
        "estimated_cost_usd",
        "id",
        "incident_id",
        "input_characters",
        "input_tokens",
        "insufficient_evidence",
        "justification",
        "latency_ms",
        "log_evidence_event_count",
        "log_evidence_sha256",
        "log_evidence_version",
        "log_submission_id",
        "missing_information",
        "model",
        "output_tokens",
        "prompt_version",
        "provider",
        "recommended_priority",
        "recommended_severity",
        "redaction_count",
        "request_id",
        "status",
        "suggested_category",
        "summary",
        "total_tokens",
    }

    assert set(Base.metadata.tables["ai_analyses"].columns.keys()) == expected


def test_analysis_primary_key() -> None:
    primary_key = Base.metadata.tables["ai_analyses"].primary_key

    assert list(primary_key.columns.keys()) == ["id"]


def test_analysis_foreign_key() -> None:
    foreign_keys = Base.metadata.tables["ai_analyses"].c.incident_id.foreign_keys

    assert len(foreign_keys) == 1

    foreign_key = next(iter(foreign_keys))

    assert foreign_key.target_fullname == "incidents.id"
    assert foreign_key.ondelete == "CASCADE"


def test_analysis_status_values() -> None:
    assert {status.value for status in AIAnalysisStatus} == {
        "succeeded",
        "failed",
    }


@pytest.mark.parametrize(
    "column_name",
    [
        "id",
        "incident_id",
        "status",
        "provider",
        "model",
        "prompt_version",
        "created_at",
    ],
)
def test_required_columns(column_name: str) -> None:
    column = Base.metadata.tables["ai_analyses"].columns[column_name]

    assert column.nullable is False


@pytest.mark.parametrize(
    "column_name",
    [
        "suggested_category",
        "recommended_priority",
        "recommended_severity",
        "summary",
        "justification",
        "confidence",
        "insufficient_evidence",
        "missing_information",
        "request_id",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cached_input_tokens",
        "estimated_cost_usd",
        "latency_ms",
        "redaction_count",
        "input_characters",
        "error_code",
        "error_message",
    ],
)
def test_optional_columns(column_name: str) -> None:
    column = Base.metadata.tables["ai_analyses"].columns[column_name]

    assert column.nullable is True


@pytest.mark.parametrize(
    "column_name",
    ["incident_id", "status", "created_at"],
)
def test_analysis_indexes(column_name: str) -> None:
    indexed_columns = {
        column.name
        for index in Base.metadata.tables["ai_analyses"].indexes
        for column in index.columns
    }

    assert column_name in indexed_columns


def test_missing_information_jsonb() -> None:
    column = Base.metadata.tables["ai_analyses"].c.missing_information

    assert isinstance(column.type, JSONB)
    assert column.type.none_as_null is True


def test_estimated_cost_precision() -> None:
    column_type = Base.metadata.tables["ai_analyses"].c.estimated_cost_usd.type

    assert isinstance(column_type, Numeric)
    assert column_type.precision == 18
    assert column_type.scale == 10
    assert column_type.asdecimal is True


def test_created_at_server_default() -> None:
    column = Base.metadata.tables["ai_analyses"].c.created_at

    assert column.server_default is not None


@pytest.mark.parametrize(
    "constraint_name",
    [
        "confidence_range",
        "input_tokens_nonnegative",
        "output_tokens_nonnegative",
        "total_tokens_nonnegative",
        "cached_tokens_nonnegative",
        "cached_tokens_range",
        "token_total_consistency",
        "latency_range",
        "cost_range",
        "redaction_count_nonnegative",
        "input_characters_positive",
        "missing_information_array",
        "execution_status_consistency",
    ],
)
def test_analysis_constraints(constraint_name: str) -> None:
    constraint_names = {
        constraint.name
        for constraint in Base.metadata.tables["ai_analyses"].constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert f"ck_ai_analyses_{constraint_name}" in constraint_names


def test_successful_analysis_initialization() -> None:
    incident_id = uuid4()

    analysis = AIAnalysis(
        incident_id=incident_id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connection failure.",
        justification="The application cannot connect.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        input_tokens=1000,
        output_tokens=200,
        total_tokens=1200,
        cached_input_tokens=100,
        estimated_cost_usd=Decimal("0.0015000000"),
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
    )

    assert analysis.incident_id == incident_id
    assert analysis.status == AIAnalysisStatus.SUCCEEDED
    assert analysis.suggested_category == "database"
    assert analysis.confidence == 0.90
    assert analysis.total_tokens == 1200
    assert analysis.estimated_cost_usd == Decimal("0.0015000000")
    assert analysis.error_code is None
    assert analysis.error_message is None


def test_failed_analysis_initialization() -> None:
    analysis = AIAnalysis(
        incident_id=uuid4(),
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
    )

    assert analysis.status == AIAnalysisStatus.FAILED
    assert analysis.error_code == "provider_timeout"
    assert analysis.error_message == "The AI request timed out."
    assert analysis.summary is None
    assert analysis.confidence is None
    assert analysis.total_tokens is None
    assert analysis.estimated_cost_usd is None


def test_unknown_priority_supported() -> None:
    analysis = AIAnalysis(
        incident_id=uuid4(),
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="unknown",
        recommended_priority=None,
        recommended_severity="unknown",
        summary="Insufficient incident information.",
        justification="Technical impact cannot be determined.",
        confidence=0.10,
        insufficient_evidence=True,
        missing_information=["Affected users"],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        latency_ms=100.0,
        redaction_count=0,
        input_characters=3000,
    )

    assert analysis.recommended_priority is None
    assert analysis.insufficient_evidence is True
    assert analysis.missing_information == ["Affected users"]
