from dataclasses import FrozenInstanceError

import pytest

from app.core.config import Settings
from app.logs.detector import DiagnosticDetector
from app.logs.evidence_contracts import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
)
from app.logs.normalizer import LogNormalizer
from app.logs.ranker import (
    CATEGORY_SCORES,
    MAX_FINDING_SCORE,
    MAX_RECURRENCE_SCORE,
    SEVERITY_SCORES,
    DiagnosticRanker,
)
from app.logs.ranking_contracts import (
    RankedDiagnosticReport,
    RankedFinding,
)
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat, LogSeverity


@pytest.fixture
def ranker() -> DiagnosticRanker:
    return DiagnosticRanker()


def make_finding(
    position: int = 1,
    severity: LogSeverity = LogSeverity.ERROR,
    category: DiagnosticCategory = DiagnosticCategory.DATABASE,
    rule_id: str = "DB-002",
) -> DiagnosticFinding:
    return DiagnosticFinding(
        position=position,
        category=category,
        rule_id=rule_id,
        description="Synthetic diagnostic indicator.",
        severity=severity,
    )


def make_report(
    *findings: DiagnosticFinding,
    entry_count: int = 10,
) -> DiagnosticReport:
    return DiagnosticReport(
        entry_count=entry_count,
        findings=findings,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (LogSeverity.TRACE, 0),
        (LogSeverity.DEBUG, 2),
        (LogSeverity.INFO, 5),
        (LogSeverity.WARNING, 20),
        (LogSeverity.ERROR, 40),
        (LogSeverity.CRITICAL, 60),
        (LogSeverity.UNKNOWN, 10),
    ],
)
def test_severity_scores(
    ranker: DiagnosticRanker,
    severity: LogSeverity,
    expected: int,
) -> None:
    finding = make_finding(
        severity=severity,
        category=DiagnosticCategory.GENERAL,
        rule_id="SEV-001",
    )

    result = ranker.rank(make_report(finding))

    ranked = result.findings[0]

    assert ranked.score == expected
    assert ranked.severity_score == expected
    assert ranked.specificity_score == 0
    assert ranked.category_score == 0
    assert ranked.recurrence_score == 0
    assert ranked.occurrence_count == 1


@pytest.mark.parametrize(
    "category",
    list(DiagnosticCategory),
)
def test_category_scoring(
    ranker: DiagnosticRanker,
    category: DiagnosticCategory,
) -> None:
    finding = make_finding(
        category=category,
        severity=LogSeverity.INFO,
    )

    ranked = ranker.rank(make_report(finding)).findings[0]

    expected_specificity = 0 if category == DiagnosticCategory.GENERAL else 25

    expected_category = {
        DiagnosticCategory.SECURITY: 10,
        DiagnosticCategory.INFRASTRUCTURE: 5,
    }.get(category, 0)

    assert ranked.specificity_score == expected_specificity
    assert ranked.category_score == expected_category

    assert ranked.score == (5 + expected_specificity + expected_category)


@pytest.mark.parametrize(
    ("occurrence_count", "expected_bonus"),
    [
        (1, 0),
        (2, 3),
        (3, 6),
        (4, 9),
        (5, 12),
        (6, 15),
        (7, 15),
        (10, 15),
        (100, 15),
    ],
)
def test_recurrence_scoring(
    ranker: DiagnosticRanker,
    occurrence_count: int,
    expected_bonus: int,
) -> None:
    findings = tuple(
        make_finding(position=position)
        for position in range(
            1,
            occurrence_count + 1,
        )
    )

    result = ranker.rank(
        make_report(
            *findings,
            entry_count=occurrence_count,
        )
    )

    assert result.finding_count == occurrence_count

    for ranked in result.findings:
        assert ranked.occurrence_count == occurrence_count
        assert ranked.recurrence_score == expected_bonus
        assert ranked.score == 65 + expected_bonus


def test_maximum_possible_score(
    ranker: DiagnosticRanker,
) -> None:
    findings = tuple(
        make_finding(
            position=position,
            severity=LogSeverity.CRITICAL,
            category=DiagnosticCategory.SECURITY,
            rule_id="SEC-001",
        )
        for position in range(1, 7)
    )

    result = ranker.rank(make_report(*findings))

    assert MAX_FINDING_SCORE == 110

    assert all(item.score == MAX_FINDING_SCORE for item in result.findings)

    assert all(
        item.recurrence_score == MAX_RECURRENCE_SCORE for item in result.findings
    )


def test_score_components_sum_correctly(
    ranker: DiagnosticRanker,
) -> None:
    finding = make_finding(
        category=DiagnosticCategory.SECURITY,
        severity=LogSeverity.ERROR,
        rule_id="SEC-001",
    )

    ranked = ranker.rank(make_report(finding)).findings[0]

    assert ranked.score == (
        ranked.severity_score
        + ranked.specificity_score
        + ranked.category_score
        + ranked.recurrence_score
    )


def test_specific_indicator_outranks_general_indicator(
    ranker: DiagnosticRanker,
) -> None:
    general = make_finding(
        category=DiagnosticCategory.GENERAL,
        rule_id="SEV-001",
    )

    specific = make_finding(
        category=DiagnosticCategory.DATABASE,
        rule_id="DB-002",
    )

    result = ranker.rank(make_report(general, specific))

    assert result.findings[0].finding == specific
    assert result.findings[1].finding == general

    assert result.findings[0].score == 65
    assert result.findings[1].score == 40


def test_security_category_bonus(
    ranker: DiagnosticRanker,
) -> None:
    database = make_finding(
        category=DiagnosticCategory.DATABASE,
        rule_id="DB-002",
    )

    security = make_finding(
        category=DiagnosticCategory.SECURITY,
        rule_id="SEC-001",
    )

    result = ranker.rank(make_report(database, security))

    assert result.findings[0].finding == security
    assert result.findings[0].score == 75
    assert result.findings[1].score == 65


def test_infrastructure_category_bonus(
    ranker: DiagnosticRanker,
) -> None:
    database = make_finding(
        category=DiagnosticCategory.DATABASE,
        rule_id="DB-002",
    )

    infrastructure = make_finding(
        category=DiagnosticCategory.INFRASTRUCTURE,
        rule_id="INFRA-001",
    )

    result = ranker.rank(make_report(database, infrastructure))

    assert result.findings[0].finding == infrastructure
    assert result.findings[0].score == 70
    assert result.findings[1].score == 65


def test_higher_severity_ranked_first(
    ranker: DiagnosticRanker,
) -> None:
    lower = make_finding(
        position=1,
        severity=LogSeverity.WARNING,
    )

    higher = make_finding(
        position=2,
        severity=LogSeverity.CRITICAL,
    )

    result = ranker.rank(make_report(lower, higher))

    assert result.findings[0].finding == higher
    assert result.findings[1].finding == lower


def test_recurrence_can_increase_priority(
    ranker: DiagnosticRanker,
) -> None:
    single = make_finding(
        position=1,
        rule_id="DB-001",
    )

    recurring_first = make_finding(
        position=2,
        rule_id="DB-002",
    )

    recurring_second = make_finding(
        position=3,
        rule_id="DB-002",
    )

    result = ranker.rank(
        make_report(
            single,
            recurring_first,
            recurring_second,
        )
    )

    assert [item.finding.rule_id for item in result.findings] == [
        "DB-002",
        "DB-002",
        "DB-001",
    ]

    assert result.findings[0].score == 68
    assert result.findings[2].score == 65


def test_recurrence_is_rule_specific(
    ranker: DiagnosticRanker,
) -> None:
    first = make_finding(
        position=1,
        rule_id="DB-001",
    )

    second = make_finding(
        position=2,
        rule_id="DB-002",
    )

    result = ranker.rank(make_report(first, second))

    assert all(item.occurrence_count == 1 for item in result.findings)

    assert all(item.recurrence_score == 0 for item in result.findings)


def test_equal_score_uses_severity_tiebreaker(
    ranker: DiagnosticRanker,
) -> None:
    specific = make_finding(
        position=1,
        severity=LogSeverity.INFO,
        category=DiagnosticCategory.SECURITY,
        rule_id="SEC-001",
    )

    general = make_finding(
        position=2,
        severity=LogSeverity.ERROR,
        category=DiagnosticCategory.GENERAL,
        rule_id="SEV-001",
    )

    result = ranker.rank(make_report(specific, general))

    assert result.findings[0].score == 40
    assert result.findings[1].score == 40

    assert result.findings[0].finding == general
    assert result.findings[1].finding == specific


def test_equal_scores_use_event_position(
    ranker: DiagnosticRanker,
) -> None:
    first = make_finding(position=1)
    second = make_finding(position=2)
    third = make_finding(position=3)

    result = ranker.rank(make_report(third, second, first))

    assert [item.finding.position for item in result.findings] == [1, 2, 3]


def test_equal_positions_use_rule_identifier(
    ranker: DiagnosticRanker,
) -> None:
    first = make_finding(rule_id="DB-001")
    second = make_finding(rule_id="DB-002")
    third = make_finding(rule_id="DB-003")

    result = ranker.rank(make_report(third, second, first))

    assert [item.finding.rule_id for item in result.findings] == [
        "DB-001",
        "DB-002",
        "DB-003",
    ]


def test_negative_entry_count_rejected(
    ranker: DiagnosticRanker,
) -> None:
    report = make_report(entry_count=-1)

    with pytest.raises(
        ValueError,
        match="cannot be negative",
    ):
        ranker.rank(report)


@pytest.mark.parametrize(
    "position",
    [-1, 0, 11, 100],
)
def test_invalid_event_positions_rejected(
    ranker: DiagnosticRanker,
    position: int,
) -> None:
    report = make_report(make_finding(position=position))

    with pytest.raises(
        ValueError,
        match="invalid event position",
    ):
        ranker.rank(report)


def test_duplicate_finding_rejected(
    ranker: DiagnosticRanker,
) -> None:
    finding = make_finding()

    report = make_report(finding, finding)

    with pytest.raises(
        ValueError,
        match="duplicate findings",
    ):
        ranker.rank(report)


def test_multiple_rules_per_event_allowed(
    ranker: DiagnosticRanker,
) -> None:
    result = ranker.rank(
        make_report(
            make_finding(rule_id="DB-001"),
            make_finding(rule_id="DB-002"),
        )
    )

    assert result.finding_count == 2
    assert result.affected_entry_count == 1


@pytest.mark.parametrize(
    "entry_count",
    [0, 1, 100],
)
def test_empty_diagnostic_report(
    ranker: DiagnosticRanker,
    entry_count: int,
) -> None:
    result = ranker.rank(make_report(entry_count=entry_count))

    assert isinstance(result, RankedDiagnosticReport)
    assert result.entry_count == entry_count
    assert result.findings == ()
    assert result.finding_count == 0
    assert result.affected_entry_count == 0
    assert result.has_findings is False


def test_ranked_report_aggregation(
    ranker: DiagnosticRanker,
) -> None:
    report = make_report(
        make_finding(
            position=1,
            rule_id="DB-001",
        ),
        make_finding(
            position=1,
            rule_id="DB-002",
        ),
        make_finding(
            position=2,
            rule_id="DB-002",
        ),
    )

    result = ranker.rank(report)

    assert result.entry_count == 10
    assert result.finding_count == 3
    assert result.affected_entry_count == 2
    assert result.has_findings is True


def test_ranker_preserves_original_finding(
    ranker: DiagnosticRanker,
) -> None:
    finding = make_finding()

    result = ranker.rank(make_report(finding))

    assert isinstance(
        result.findings[0],
        RankedFinding,
    )

    assert result.findings[0].finding is finding


def test_original_report_not_modified(
    ranker: DiagnosticRanker,
) -> None:
    first = make_finding(
        position=1,
        severity=LogSeverity.INFO,
    )

    second = make_finding(
        position=2,
        severity=LogSeverity.CRITICAL,
    )

    report = make_report(first, second)

    ranker.rank(report)

    assert report.findings == (first, second)


def test_ranked_finding_is_immutable(
    ranker: DiagnosticRanker,
) -> None:
    result = ranker.rank(make_report(make_finding()))

    with pytest.raises(FrozenInstanceError):
        type(result.findings[0]).__setattr__(result.findings[0], "score", 1000)


def test_ranked_report_is_immutable(
    ranker: DiagnosticRanker,
) -> None:
    result = ranker.rank(make_report(make_finding()))

    with pytest.raises(FrozenInstanceError):
        type(result).__setattr__(result, "entry_count", 1000)


def test_ranking_is_deterministic(
    ranker: DiagnosticRanker,
) -> None:
    report = make_report(
        make_finding(position=2),
        make_finding(position=1),
    )

    assert ranker.rank(report) == ranker.rank(report)


def test_ranking_independent_of_input_order(
    ranker: DiagnosticRanker,
) -> None:
    first = make_finding(position=1)
    second = make_finding(position=2)

    forward = ranker.rank(make_report(first, second))

    backward = ranker.rank(make_report(second, first))

    assert forward == backward


def test_ranker_does_not_retain_recurrence(
    ranker: DiagnosticRanker,
) -> None:
    first = ranker.rank(
        make_report(
            make_finding(position=1),
            make_finding(position=2),
        )
    )

    second = ranker.rank(make_report(make_finding()))

    assert first.findings[0].occurrence_count == 2
    assert second.findings[0].occurrence_count == 1
    assert second.findings[0].recurrence_score == 0


def test_all_severities_have_scores() -> None:
    assert set(SEVERITY_SCORES) == set(LogSeverity)


def test_category_bonus_values() -> None:
    assert CATEGORY_SCORES[DiagnosticCategory.SECURITY] == 10

    assert CATEGORY_SCORES[DiagnosticCategory.INFRASTRUCTURE] == 5


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b"<logs>"
            b'<entry severity="INFO" message="Ready"/>'
            b'<entry severity="ERROR" '
            b'message="Database connection failed"/>'
            b'<entry severity="CRITICAL" '
            b'message="Invalid signature"/>'
            b"</logs>",
        ),
        (
            LogFormat.JSON,
            b'[{"severity":"INFO","message":"Ready"},'
            b'{"severity":"ERROR",'
            b'"message":"Database connection failed"},'
            b'{"severity":"CRITICAL",'
            b'"message":"Invalid signature"}]',
        ),
        (
            LogFormat.TEXT,
            b"INFO Ready\nERROR Database connection failed\nCRITICAL Invalid signature",
        ),
    ],
)
def test_end_to_end_evidence_ranking(
    ranker: DiagnosticRanker,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    settings = Settings(_env_file=None)

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    diagnostics = DiagnosticDetector().detect(sanitized)

    result = ranker.rank(diagnostics)

    assert result.entry_count == 3
    assert result.finding_count == 4
    assert result.affected_entry_count == 2

    assert result.findings[0].finding.rule_id == "SEC-001"
    assert result.findings[0].finding.position == 3
    assert result.findings[0].score == 95

    assert [item.score for item in result.findings] == [95, 65, 63, 43]


def test_ranked_report_does_not_copy_sensitive_content(
    ranker: DiagnosticRanker,
) -> None:
    settings = Settings(_env_file=None)
    canary = "SYNTHETIC_SECRET_CANARY"

    payload = b"ERROR Authentication failed password=SYNTHETIC_SECRET_CANARY"

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    report = DiagnosticDetector().detect(sanitized)

    result = ranker.rank(report)

    assert sanitized.redaction_count > 0
    assert result.has_findings is True
    assert canary not in repr(result)

    assert result.findings[0].finding.rule_id == "AUTH-001"
