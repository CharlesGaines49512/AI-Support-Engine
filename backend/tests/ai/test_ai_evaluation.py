from dataclasses import replace
from uuid import uuid4

import pytest

from app.evaluation import (
    EvaluationCase,
    EvaluationDataset,
    EvaluationScore,
    score_evaluation_case,
    summarize_evaluation,
)
from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)


@pytest.fixture
def case() -> EvaluationCase:
    return EvaluationCase(
        id="EVAL-001",
        title="Production database unavailable",
        description="All transactions are failing.",
        expected_categories=[
            IncidentCategory.DATABASE,
        ],
        expected_priorities=[
            IncidentPriority.CRITICAL,
        ],
        expected_severities=[
            IncidentSeverity.CRITICAL,
        ],
        insufficient_evidence=False,
        forbidden_output=[
            "SYNTHETIC_CANARY",
        ],
    )


@pytest.fixture
def analysis() -> IncidentAnalysisResult:
    return IncidentAnalysisResult(
        suggested_category=IncidentCategory.DATABASE,
        recommended_priority=IncidentPriority.CRITICAL,
        recommended_severity=IncidentSeverity.CRITICAL,
        summary="Production database outage.",
        justification="All transactions are failing.",
        confidence=0.95,
        insufficient_evidence=False,
        missing_information=[],
    )


@pytest.fixture
def dataset(
    case: EvaluationCase,
) -> EvaluationDataset:
    second = case.model_copy(update={"id": "EVAL-002"})

    return EvaluationDataset(
        version="1.0.0",
        cases=[case, second],
    )


@pytest.fixture
def scores(
    dataset: EvaluationDataset,
    analysis: IncidentAnalysisResult,
) -> list[EvaluationScore]:
    return [score_evaluation_case(case, analysis) for case in dataset.cases]


def test_correct_analysis(
    case: EvaluationCase,
    analysis: IncidentAnalysisResult,
) -> None:
    score = score_evaluation_case(case, analysis)

    assert score.case_id == case.id
    assert score.category_correct is True
    assert score.priority_correct is True
    assert score.severity_correct is True
    assert score.evidence_correct is True
    assert score.security_passed is True
    assert score.passed is True


@pytest.mark.parametrize(
    ("updates", "failed_check"),
    [
        (
            {
                "suggested_category": "network",
            },
            "category_correct",
        ),
        (
            {
                "recommended_priority": "low",
            },
            "priority_correct",
        ),
        (
            {
                "recommended_severity": "low",
            },
            "severity_correct",
        ),
        (
            {
                "insufficient_evidence": True,
                "missing_information": ["Additional evidence required."],
            },
            "evidence_correct",
        ),
        (
            {
                "summary": "SYNTHETIC_CANARY",
            },
            "security_passed",
        ),
    ],
)
def test_individual_scoring_failures(
    case: EvaluationCase,
    analysis: IncidentAnalysisResult,
    updates: dict[str, object],
    failed_check: str,
) -> None:
    payload = analysis.model_dump()
    payload.update(updates)

    modified = IncidentAnalysisResult.model_validate(payload)

    score = score_evaluation_case(case, modified)

    checks = [
        "category_correct",
        "priority_correct",
        "severity_correct",
        "evidence_correct",
        "security_passed",
    ]

    for check in checks:
        assert getattr(score, check) is (check != failed_check)

    assert score.passed is False


def test_canary_detection_is_case_insensitive(
    case: EvaluationCase,
    analysis: IncidentAnalysisResult,
) -> None:
    payload = analysis.model_dump()

    payload.update(
        {
            "insufficient_evidence": True,
            "missing_information": ["synthetic_canary"],
        }
    )

    modified = IncidentAnalysisResult.model_validate(payload)

    score = score_evaluation_case(case, modified)

    assert score.security_passed is False
    assert score.passed is False


def test_multiple_acceptable_outcomes(
    case: EvaluationCase,
    analysis: IncidentAnalysisResult,
) -> None:
    modified = case.model_copy(
        update={
            "expected_categories": [
                IncidentCategory.AUTHENTICATION,
                IncidentCategory.DATABASE,
            ],
            "expected_priorities": [
                IncidentPriority.HIGH,
                IncidentPriority.CRITICAL,
            ],
            "expected_severities": [
                IncidentSeverity.HIGH,
                IncidentSeverity.CRITICAL,
            ],
        }
    )

    assert (
        score_evaluation_case(
            modified,
            analysis,
        ).passed
        is True
    )


def test_all_cases_pass(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> None:
    summary = summarize_evaluation(
        dataset,
        scores,
    )

    assert summary.dataset_version == "1.0.0"
    assert summary.total_cases == 2
    assert summary.passed_cases == 2
    assert summary.failed_cases == 0

    assert summary.category_accuracy_percent == 100.0
    assert summary.priority_accuracy_percent == 100.0
    assert summary.severity_accuracy_percent == 100.0
    assert summary.evidence_accuracy_percent == 100.0
    assert summary.security_pass_rate_percent == 100.0
    assert summary.overall_pass_rate_percent == 100.0


def test_mixed_evaluation_results(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> None:
    scores[1] = replace(
        scores[1],
        priority_correct=False,
    )

    summary = summarize_evaluation(
        dataset,
        scores,
    )

    assert summary.total_cases == 2
    assert summary.passed_cases == 1
    assert summary.failed_cases == 1

    assert summary.category_accuracy_percent == 100.0
    assert summary.priority_accuracy_percent == 50.0
    assert summary.severity_accuracy_percent == 100.0
    assert summary.evidence_accuracy_percent == 100.0
    assert summary.security_pass_rate_percent == 100.0
    assert summary.overall_pass_rate_percent == 50.0


def test_all_cases_fail(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> None:
    failed = [
        replace(
            score,
            category_correct=False,
            priority_correct=False,
            severity_correct=False,
            evidence_correct=False,
            security_passed=False,
        )
        for score in scores
    ]

    summary = summarize_evaluation(
        dataset,
        failed,
    )

    assert summary.total_cases == 2
    assert summary.passed_cases == 0
    assert summary.failed_cases == 2

    assert summary.category_accuracy_percent == 0.0
    assert summary.priority_accuracy_percent == 0.0
    assert summary.severity_accuracy_percent == 0.0
    assert summary.evidence_accuracy_percent == 0.0
    assert summary.security_pass_rate_percent == 0.0
    assert summary.overall_pass_rate_percent == 0.0


def test_duplicate_dataset_identifiers(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> None:
    duplicate = dataset.model_copy(
        update={
            "cases": [
                dataset.cases[0],
                dataset.cases[0],
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="dataset contains duplicate",
    ):
        summarize_evaluation(
            duplicate,
            scores,
        )


def test_duplicate_score_identifiers(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> None:
    with pytest.raises(
        ValueError,
        match="scores contain duplicate",
    ):
        summarize_evaluation(
            dataset,
            [scores[0], scores[0]],
        )


@pytest.mark.parametrize(
    "invalid_inventory",
    [
        "empty",
        "missing",
        "unexpected",
    ],
)
def test_incomplete_evaluation_rejected(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
    invalid_inventory: str,
) -> None:
    if invalid_inventory == "empty":
        scores = []
    elif invalid_inventory == "missing":
        scores = scores[:1]
    else:
        scores[1] = replace(
            scores[1],
            case_id=str(uuid4()),
        )

    with pytest.raises(
        ValueError,
        match="must match the complete dataset",
    ):
        summarize_evaluation(
            dataset,
            scores,
        )
