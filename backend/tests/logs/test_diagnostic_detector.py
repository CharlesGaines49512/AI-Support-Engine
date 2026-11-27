from dataclasses import FrozenInstanceError, replace

import pytest

from app.core.config import Settings
from app.logs.detection_rules import DETECTION_RULES
from app.logs.detector import DiagnosticDetector
from app.logs.evidence_contracts import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
)
from app.logs.normalizer import LogNormalizer
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat, LogSeverity


@pytest.fixture
def detector() -> DiagnosticDetector:
    return DiagnosticDetector()


def make_entry(
    message: str,
    position: int = 1,
    severity: LogSeverity = LogSeverity.INFO,
) -> SanitizedLogEntry:
    return SanitizedLogEntry(
        position=position,
        severity=severity,
        message=message,
    )


def make_log(
    *entries: SanitizedLogEntry,
) -> SanitizedLog:
    return SanitizedLog(
        source_format=LogFormat.JSON,
        payload_bytes=1000,
        entries=entries,
    )


@pytest.mark.parametrize(
    ("message", "rule_id", "category"),
    [
        (
            "Authentication failed",
            "AUTH-001",
            DiagnosticCategory.AUTHENTICATION,
        ),
        (
            "Invalid credentials",
            "AUTH-001",
            DiagnosticCategory.AUTHENTICATION,
        ),
        (
            "Login failed",
            "AUTH-001",
            DiagnosticCategory.AUTHENTICATION,
        ),
        (
            "HTTP 401",
            "AUTH-002",
            DiagnosticCategory.AUTHENTICATION,
        ),
        (
            "HTTP/1.1 401 Unauthorized",
            "AUTH-002",
            DiagnosticCategory.AUTHENTICATION,
        ),
        (
            "Access denied",
            "AUTHZ-001",
            DiagnosticCategory.AUTHORIZATION,
        ),
        (
            "Permission denied",
            "AUTHZ-001",
            DiagnosticCategory.AUTHORIZATION,
        ),
        (
            "HTTP 403",
            "AUTHZ-002",
            DiagnosticCategory.AUTHORIZATION,
        ),
        (
            "403 Forbidden",
            "AUTHZ-002",
            DiagnosticCategory.AUTHORIZATION,
        ),
        (
            "SQLException encountered",
            "DB-001",
            DiagnosticCategory.DATABASE,
        ),
        (
            "SQLSTATE 08006",
            "DB-001",
            DiagnosticCategory.DATABASE,
        ),
        (
            "Database connection failed",
            "DB-002",
            DiagnosticCategory.DATABASE,
        ),
        (
            "Database unavailable",
            "DB-002",
            DiagnosticCategory.DATABASE,
        ),
        (
            "Deadlock detected",
            "DB-003",
            DiagnosticCategory.DATABASE,
        ),
        (
            "Lock wait timeout",
            "DB-003",
            DiagnosticCategory.DATABASE,
        ),
        (
            "Connection refused",
            "NET-001",
            DiagnosticCategory.NETWORK,
        ),
        (
            "Connection reset",
            "NET-001",
            DiagnosticCategory.NETWORK,
        ),
        (
            "Network unreachable",
            "NET-001",
            DiagnosticCategory.NETWORK,
        ),
        (
            "DNS resolution failed",
            "NET-002",
            DiagnosticCategory.NETWORK,
        ),
        (
            "NXDOMAIN returned",
            "NET-002",
            DiagnosticCategory.NETWORK,
        ),
        (
            "NullPointerException encountered",
            "APP-001",
            DiagnosticCategory.APPLICATION,
        ),
        (
            "Unhandled exception",
            "APP-001",
            DiagnosticCategory.APPLICATION,
        ),
        (
            "HTTP 500",
            "APP-002",
            DiagnosticCategory.APPLICATION,
        ),
        (
            "Application crashed",
            "APP-002",
            DiagnosticCategory.APPLICATION,
        ),
        (
            "Webhook failed",
            "INT-001",
            DiagnosticCategory.INTEGRATION,
        ),
        (
            "HTTP 502",
            "INT-001",
            DiagnosticCategory.INTEGRATION,
        ),
        (
            "TK-ERR",
            "INT-002",
            DiagnosticCategory.INTEGRATION,
        ),
        (
            "Ticketing failed",
            "INT-002",
            DiagnosticCategory.INTEGRATION,
        ),
        (
            "Invalid configuration",
            "CFG-001",
            DiagnosticCategory.CONFIGURATION,
        ),
        (
            "Missing environment variable",
            "CFG-001",
            DiagnosticCategory.CONFIGURATION,
        ),
        (
            "Request timed out",
            "PERF-001",
            DiagnosticCategory.PERFORMANCE,
        ),
        (
            "TimeoutException",
            "PERF-001",
            DiagnosticCategory.PERFORMANCE,
        ),
        (
            "HTTP 504",
            "PERF-001",
            DiagnosticCategory.PERFORMANCE,
        ),
        (
            "High latency",
            "PERF-002",
            DiagnosticCategory.PERFORMANCE,
        ),
        (
            "Slow query detected",
            "PERF-002",
            DiagnosticCategory.PERFORMANCE,
        ),
        (
            "Out of memory",
            "INFRA-001",
            DiagnosticCategory.INFRASTRUCTURE,
        ),
        (
            "OOMKilled",
            "INFRA-001",
            DiagnosticCategory.INFRASTRUCTURE,
        ),
        (
            "Disk full",
            "INFRA-002",
            DiagnosticCategory.INFRASTRUCTURE,
        ),
        (
            "No space left on device",
            "INFRA-002",
            DiagnosticCategory.INFRASTRUCTURE,
        ),
        (
            "SQL injection detected",
            "SEC-001",
            DiagnosticCategory.SECURITY,
        ),
        (
            "Invalid signature",
            "SEC-001",
            DiagnosticCategory.SECURITY,
        ),
        (
            "Certificate verification failed",
            "SEC-001",
            DiagnosticCategory.SECURITY,
        ),
        (
            "Schema validation failed",
            "DATA-001",
            DiagnosticCategory.DATA,
        ),
        (
            "Malformed payload",
            "DATA-001",
            DiagnosticCategory.DATA,
        ),
        (
            "JSONDecodeError",
            "DATA-001",
            DiagnosticCategory.DATA,
        ),
    ],
)
def test_supported_diagnostic_indicators(
    detector: DiagnosticDetector,
    message: str,
    rule_id: str,
    category: DiagnosticCategory,
) -> None:
    findings = detector.detect_entry(make_entry(message))

    assert any(
        finding.rule_id == rule_id and finding.category == category
        for finding in findings
    )


@pytest.mark.parametrize(
    "message",
    [
        "Application ready",
        "Database connection established",
        "Authentication successful",
        "Request completed",
        "HTTP 200 OK",
        "Configuration loaded",
        "Ticketing completed",
        "Memory allocation successful",
        "4012",
        "5000",
        "TK-ERROR",
        "Synthetic diagnostic information",
    ],
)
def test_no_indicators_in_clean_messages(
    detector: DiagnosticDetector,
    message: str,
) -> None:
    assert detector.detect_entry(make_entry(message)) == ()


@pytest.mark.parametrize(
    "message",
    [
        "DATABASE CONNECTION FAILED",
        "Database Connection Failed",
        "database connection failed",
        "DaTaBaSe CoNnEcTiOn FaIlEd",
    ],
)
def test_case_insensitive_detection(
    detector: DiagnosticDetector,
    message: str,
) -> None:
    findings = detector.detect_entry(make_entry(message))

    assert findings[0].rule_id == "DB-002"


@pytest.mark.parametrize(
    "severity",
    [
        LogSeverity.ERROR,
        LogSeverity.CRITICAL,
    ],
)
def test_explicit_error_severity(
    detector: DiagnosticDetector,
    severity: LogSeverity,
) -> None:
    findings = detector.detect_entry(
        make_entry(
            "Synthetic event",
            severity=severity,
        )
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEV-001"
    assert findings[0].severity == severity
    assert findings[0].category == DiagnosticCategory.GENERAL


@pytest.mark.parametrize(
    "severity",
    [
        LogSeverity.TRACE,
        LogSeverity.DEBUG,
        LogSeverity.INFO,
        LogSeverity.WARNING,
        LogSeverity.UNKNOWN,
    ],
)
def test_non_error_severity(
    detector: DiagnosticDetector,
    severity: LogSeverity,
) -> None:
    assert (
        detector.detect_entry(
            make_entry(
                "Synthetic event",
                severity=severity,
            )
        )
        == ()
    )


def test_exception_field_detection(
    detector: DiagnosticDetector,
) -> None:
    entry = replace(
        make_entry("Application diagnostic"),
        exception="NullPointerException",
    )

    findings = detector.detect_entry(entry)

    assert findings[0].rule_id == "APP-001"


def test_error_code_detection(
    detector: DiagnosticDetector,
) -> None:
    entry = replace(
        make_entry("Workflow diagnostic"),
        error_code="TK-ERR",
    )

    findings = detector.detect_entry(entry)

    assert findings[0].rule_id == "INT-002"


def test_unrelated_metadata_not_scanned(
    detector: DiagnosticDetector,
) -> None:
    entry = replace(
        make_entry("Ready"),
        service_name="Database connection failed",
        correlation_id="Invalid credentials",
        original_severity="SQL injection",
    )

    assert detector.detect_entry(entry) == ()


def test_duplicate_rule_matches_collapsed(
    detector: DiagnosticDetector,
) -> None:
    entry = replace(
        make_entry("Ticketing failed. Ticketing failed."),
        exception="Ticketing failed",
        error_code="TK-ERR",
    )

    findings = detector.detect_entry(entry)

    assert len(findings) == 1
    assert findings[0].rule_id == "INT-002"


def test_multiple_diagnostic_categories(
    detector: DiagnosticDetector,
) -> None:
    entry = make_entry(
        "Database connection failed: connection refused. Request timed out.",
        severity=LogSeverity.ERROR,
    )

    findings = detector.detect_entry(entry)

    assert {finding.rule_id for finding in findings} == {
        "DB-002",
        "NET-001",
        "PERF-001",
        "SEV-001",
    }

    assert {finding.category for finding in findings} == {
        DiagnosticCategory.DATABASE,
        DiagnosticCategory.NETWORK,
        DiagnosticCategory.PERFORMANCE,
        DiagnosticCategory.GENERAL,
    }


def test_event_position_preserved(
    detector: DiagnosticDetector,
) -> None:
    findings = detector.detect_entry(
        make_entry(
            "Database connection failed",
            position=4,
        )
    )

    assert findings[0].position == 4


def test_diagnostic_report_aggregation(
    detector: DiagnosticDetector,
) -> None:
    report = detector.detect(
        make_log(
            make_entry("Application ready", 1),
            make_entry("Database connection failed", 2),
            make_entry(
                "Connection refused",
                3,
                LogSeverity.ERROR,
            ),
        )
    )

    assert report.entry_count == 3
    assert report.finding_count == 3
    assert report.affected_entry_count == 2
    assert report.has_findings is True

    assert [finding.position for finding in report.findings] == [2, 3, 3]


def test_multiple_findings_one_affected_event(
    detector: DiagnosticDetector,
) -> None:
    report = detector.detect(
        make_log(
            make_entry(
                "Database connection failed",
                severity=LogSeverity.CRITICAL,
            )
        )
    )

    assert report.finding_count == 2
    assert report.affected_entry_count == 1


def test_clean_report(
    detector: DiagnosticDetector,
) -> None:
    report = detector.detect(make_log(make_entry("Application ready")))

    assert report.entry_count == 1
    assert report.findings == ()
    assert report.finding_count == 0
    assert report.affected_entry_count == 0
    assert report.has_findings is False


def test_empty_report_contract() -> None:
    report = DiagnosticReport(
        entry_count=0,
        findings=(),
    )

    assert report.finding_count == 0
    assert report.affected_entry_count == 0
    assert report.has_findings is False


def test_detector_does_not_modify_source(
    detector: DiagnosticDetector,
) -> None:
    entry = make_entry("Database connection failed")

    source = make_log(entry)

    detector.detect(source)

    assert source.entries == (entry,)
    assert entry.message == "Database connection failed"


def test_detection_is_deterministic(
    detector: DiagnosticDetector,
) -> None:
    source = make_log(
        make_entry("Database connection failed"),
        make_entry("HTTP 401", 2),
    )

    assert detector.detect(source) == detector.detect(source)


def test_detector_does_not_retain_previous_findings(
    detector: DiagnosticDetector,
) -> None:
    first = detector.detect(make_log(make_entry("Database connection failed")))

    second = detector.detect(make_log(make_entry("Ready")))

    assert first.has_findings is True
    assert second.has_findings is False


def test_rule_identifiers_are_unique() -> None:
    identifiers = [rule.rule_id for rule in DETECTION_RULES]

    assert len(identifiers) == 20
    assert len(identifiers) == len(set(identifiers))


def test_rules_cover_all_diagnostic_categories() -> None:
    assert {rule.category for rule in DETECTION_RULES} == (
        set(DiagnosticCategory) - {DiagnosticCategory.GENERAL}
    )


def test_rule_descriptions_are_nonempty() -> None:
    assert all(rule.description.strip() for rule in DETECTION_RULES)


def test_rule_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        type(DETECTION_RULES[0]).__setattr__(DETECTION_RULES[0], "rule_id", "MODIFIED")


def test_finding_is_immutable() -> None:
    finding = DiagnosticFinding(
        position=1,
        category=DiagnosticCategory.DATABASE,
        rule_id="DB-002",
        description="Database indicator detected.",
        severity=LogSeverity.ERROR,
    )

    with pytest.raises(FrozenInstanceError):
        type(finding).__setattr__(finding, "position", 2)


def test_report_is_immutable() -> None:
    report = DiagnosticReport(
        entry_count=1,
        findings=(),
    )

    with pytest.raises(FrozenInstanceError):
        type(report).__setattr__(report, "entry_count", 2)


def test_findings_do_not_copy_log_content(
    detector: DiagnosticDetector,
) -> None:
    canary = "SYNTHETIC_DIAGNOSTIC_CANARY"

    report = detector.detect(
        make_log(make_entry(f"Database connection failed: {canary}"))
    )

    assert report.has_findings is True
    assert canary not in repr(report)

    assert all(canary not in finding.description for finding in report.findings)


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<entry severity="ERROR">'
            b"<message>Database connection failed</message>"
            b"</entry>",
        ),
        (
            LogFormat.JSON,
            b'{"severity":"ERROR","message":"Database connection failed"}',
        ),
        (
            LogFormat.TEXT,
            b"ERROR Database connection failed",
        ),
    ],
)
def test_end_to_end_diagnostic_detection(
    detector: DiagnosticDetector,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    settings = Settings(_env_file=None)

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    report = detector.detect(sanitized)

    assert report.entry_count == 1
    assert report.affected_entry_count == 1

    assert {finding.rule_id for finding in report.findings} == {"DB-002", "SEV-001"}


def test_detection_after_credential_redaction(
    detector: DiagnosticDetector,
) -> None:
    settings = Settings(_env_file=None)

    normalized = LogNormalizer(settings).parse_and_normalize(
        b'{"severity":"ERROR",'
        b'"message":"Authentication failed '
        b'password=SYNTHETIC_SECRET_CANARY"}',
        LogFormat.JSON,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    report = detector.detect(sanitized)

    assert sanitized.redaction_count > 0

    assert "SYNTHETIC_SECRET_CANARY" not in (sanitized.entries[0].message)

    assert {finding.rule_id for finding in report.findings} == {"AUTH-001", "SEV-001"}

    assert "SYNTHETIC_SECRET_CANARY" not in repr(report)
