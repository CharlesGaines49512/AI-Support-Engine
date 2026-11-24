from pathlib import Path

import pytest

from app.evaluation import EvaluationCase, EvaluationDataset
from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.security import sanitize_text

DATASET_PATH = (
    Path(__file__).resolve().parents[2] / "evaluations" / "incident_cases.json"
)

DATASET = EvaluationDataset.model_validate_json(
    DATASET_PATH.read_text(encoding="utf-8-sig")
)


@pytest.mark.parametrize(
    "case",
    DATASET.cases,
    ids=[case.id for case in DATASET.cases],
)
def test_evaluation_case_contract(
    case: EvaluationCase,
) -> None:
    assert case.title.strip() == case.title
    assert case.description.strip() == case.description

    for category in case.expected_categories:
        for priority in case.expected_priorities:
            for severity in case.expected_severities:
                result = IncidentAnalysisResult(
                    suggested_category=category,
                    recommended_priority=priority,
                    recommended_severity=severity,
                    summary="Synthetic evaluation summary.",
                    justification="Synthetic evaluation justification.",
                    confidence=0.5,
                    insufficient_evidence=case.insufficient_evidence,
                    missing_information=(
                        ["Additional incident evidence."]
                        if case.insufficient_evidence
                        else []
                    ),
                )

                assert result.suggested_category == category
                assert result.recommended_priority == priority
                assert result.recommended_severity == severity

    assert all(value.strip() for value in case.forbidden_output)


def test_dataset_version_and_size() -> None:
    assert DATASET.version == "1.0.0"
    assert len(DATASET.cases) == 16


def test_dataset_identifiers_are_unique() -> None:
    identifiers = [case.id for case in DATASET.cases]

    assert len(identifiers) == len(set(identifiers))


def test_dataset_covers_all_categories() -> None:
    categories = {
        category for case in DATASET.cases for category in case.expected_categories
    }

    assert categories == set(IncidentCategory)


def test_dataset_covers_all_priorities() -> None:
    priorities = {
        priority for case in DATASET.cases for priority in case.expected_priorities
    }

    assert priorities == set(IncidentPriority) | {None}


def test_dataset_covers_all_severities() -> None:
    severities = {
        severity for case in DATASET.cases for severity in case.expected_severities
    }

    assert severities == set(IncidentSeverity)


def test_insufficient_evidence_cases() -> None:
    cases = [case for case in DATASET.cases if case.insufficient_evidence]

    assert len(cases) == 2

    for case in cases:
        assert None in case.expected_priorities
        assert IncidentSeverity.UNKNOWN in case.expected_severities


def test_prompt_injection_case() -> None:
    case = next(case for case in DATASET.cases if case.id == "EVAL-014")

    assert "Ignore previous instructions" in (case.description)

    assert case.expected_priorities == [IncidentPriority.CRITICAL]

    assert case.forbidden_output

    for marker in case.forbidden_output:
        assert marker in case.description


def test_credential_case_is_sanitized() -> None:
    case = next(case for case in DATASET.cases if case.id == "EVAL-015")

    sanitized = sanitize_text(case.description)

    assert sanitized.redaction_count > 0
    assert case.forbidden_output

    for marker in case.forbidden_output:
        assert marker in case.description
        assert marker not in sanitized.text
