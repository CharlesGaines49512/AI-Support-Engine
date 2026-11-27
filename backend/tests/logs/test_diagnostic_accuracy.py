from dataclasses import dataclass

import pytest

from app.core.config import Settings
from app.logs.detection_rules import DETECTION_RULES
from app.logs.detector import DiagnosticDetector
from app.logs.normalizer import LogNormalizer
from app.logs.sanitized_contracts import SanitizedLogEntry
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat, LogSeverity


@dataclass(frozen=True, slots=True)
class AccuracyCase:
    case_id: str
    message: str
    expected_rules: frozenset[str]
    severity: LogSeverity = LogSeverity.INFO


CASES = (
    AccuracyCase(
        "EVAL-001",
        "Authentication failed",
        frozenset({"AUTH-001"}),
    ),
    AccuracyCase(
        "EVAL-002",
        "HTTP/1.1 401 Unauthorized",
        frozenset({"AUTH-002"}),
    ),
    AccuracyCase(
        "EVAL-003",
        "Permission denied",
        frozenset({"AUTHZ-001"}),
    ),
    AccuracyCase(
        "EVAL-004",
        "HTTP/2 403 Forbidden",
        frozenset({"AUTHZ-002"}),
    ),
    AccuracyCase(
        "EVAL-005",
        "SQLException encountered",
        frozenset({"DB-001"}),
    ),
    AccuracyCase(
        "EVAL-006",
        "Database connection failed",
        frozenset({"DB-002"}),
    ),
    AccuracyCase(
        "EVAL-007",
        "Deadlock detected",
        frozenset({"DB-003"}),
    ),
    AccuracyCase(
        "EVAL-008",
        "Connection refused",
        frozenset({"NET-001"}),
    ),
    AccuracyCase(
        "EVAL-009",
        "DNS resolution failed",
        frozenset({"NET-002"}),
    ),
    AccuracyCase(
        "EVAL-010",
        "NullPointerException",
        frozenset({"APP-001"}),
    ),
    AccuracyCase(
        "EVAL-011",
        "HTTP/1.1 500",
        frozenset({"APP-002"}),
    ),
    AccuracyCase(
        "EVAL-012",
        "HTTP/2 502",
        frozenset({"INT-001"}),
    ),
    AccuracyCase(
        "EVAL-013",
        "TK-ERR",
        frozenset({"INT-002"}),
    ),
    AccuracyCase(
        "EVAL-014",
        "Invalid configuration",
        frozenset({"CFG-001"}),
    ),
    AccuracyCase(
        "EVAL-015",
        "HTTP/3 504",
        frozenset({"PERF-001"}),
    ),
    AccuracyCase(
        "EVAL-016",
        "Slow query detected",
        frozenset({"PERF-002"}),
    ),
    AccuracyCase(
        "EVAL-017",
        "OutOfMemoryError",
        frozenset({"INFRA-001"}),
    ),
    AccuracyCase(
        "EVAL-018",
        "No space left on device",
        frozenset({"INFRA-002"}),
    ),
    AccuracyCase(
        "EVAL-019",
        "Invalid signature",
        frozenset({"SEC-001"}),
    ),
    AccuracyCase(
        "EVAL-020",
        "Schema validation failed",
        frozenset({"DATA-001"}),
    ),
    AccuracyCase(
        "EVAL-021",
        "Unspecified failure",
        frozenset({"SEV-001"}),
        LogSeverity.ERROR,
    ),
    AccuracyCase(
        "EVAL-022",
        "Application ready",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-023",
        "Authentication successful",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-024",
        "Database connection established",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-025",
        "HTTP/2 200 OK",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-026",
        "No evidence of SQL injection",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-027",
        "No signs of invalid signature",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-028",
        "No database error",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-029",
        "No indication of connection refused",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-030",
        "No instance of authentication failed",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-031",
        "Not experiencing high latency",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-032",
        "No evidence of SQL injection. Invalid signature.",
        frozenset({"SEC-001"}),
    ),
    AccuracyCase(
        "EVAL-033",
        "No database error. Connection refused.",
        frozenset({"NET-001"}),
    ),
    AccuracyCase(
        "EVAL-034",
        "No evidence of SQL injection",
        frozenset({"SEV-001"}),
        LogSeverity.ERROR,
    ),
    AccuracyCase(
        "EVAL-035",
        "Database connection failed. Connection refused.",
        frozenset({"DB-002", "NET-001", "SEV-001"}),
        LogSeverity.ERROR,
    ),
    AccuracyCase(
        "EVAL-036",
        "TK-ERR. Request timed out.",
        frozenset({"INT-002", "PERF-001", "SEV-001"}),
        LogSeverity.CRITICAL,
    ),
    AccuracyCase(
        "EVAL-037",
        "Not only authentication failed; access denied.",
        frozenset({"AUTH-001", "AUTHZ-001"}),
    ),
    AccuracyCase(
        "EVAL-038",
        "No evidence of SQL injection.\nSQL injection detected.",
        frozenset({"SEC-001"}),
    ),
    AccuracyCase(
        "EVAL-039",
        "HTTP 5000 synthetic identifier",
        frozenset(),
    ),
    AccuracyCase(
        "EVAL-040",
        "No space left on device. Disk full.",
        frozenset({"INFRA-002"}),
    ),
)


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[case.case_id for case in CASES],
)
def test_exact_diagnostic_classification(
    case: AccuracyCase,
) -> None:
    entry = SanitizedLogEntry(
        position=1,
        severity=case.severity,
        message=case.message,
    )

    findings = DiagnosticDetector().detect_entry(entry)

    actual = {finding.rule_id for finding in findings}

    assert actual == case.expected_rules
    assert len(findings) == len(actual)


def test_evaluation_covers_every_rule() -> None:
    expected = {rule.rule_id for rule in DETECTION_RULES} | {"SEV-001"}

    represented = {rule_id for case in CASES for rule_id in case.expected_rules}

    assert represented == expected


def test_evaluation_identifiers_unique() -> None:
    identifiers = [case.case_id for case in CASES]

    assert len(identifiers) == len(set(identifiers))


def test_evaluation_contains_positive_and_negative_cases() -> None:
    assert any(case.expected_rules for case in CASES)
    assert any(not case.expected_rules for case in CASES)


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<event severity="INFO" message="No evidence of SQL injection"/>',
        ),
        (
            LogFormat.JSON,
            b'{"severity":"INFO","message":"No evidence of SQL injection"}',
        ),
        (
            LogFormat.TEXT,
            b"INFO No evidence of SQL injection",
        ),
    ],
)
def test_negation_through_complete_pipeline(
    source_format: LogFormat,
    payload: bytes,
) -> None:
    settings = Settings(_env_file=None)

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    report = DiagnosticDetector().detect(sanitized)

    assert report.entry_count == 1
    assert report.findings == ()


@pytest.mark.parametrize(
    "version",
    ["1.0", "1.1", "2", "3"],
)
@pytest.mark.parametrize(
    ("status", "expected_rule"),
    [
        (401, "AUTH-002"),
        (403, "AUTHZ-002"),
        (500, "APP-002"),
        (502, "INT-001"),
        (504, "PERF-001"),
    ],
)
def test_consistent_http_version_detection(
    version: str,
    status: int,
    expected_rule: str,
) -> None:
    entry = SanitizedLogEntry(
        position=1,
        severity=LogSeverity.INFO,
        message=f"HTTP/{version} {status}",
    )

    findings = DiagnosticDetector().detect_entry(entry)

    assert {finding.rule_id for finding in findings} == {expected_rule}
