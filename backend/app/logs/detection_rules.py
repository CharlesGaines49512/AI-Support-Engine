import re
from dataclasses import dataclass

from app.logs.evidence_contracts import DiagnosticCategory


@dataclass(frozen=True, slots=True)
class DetectionRule:
    rule_id: str
    category: DiagnosticCategory
    description: str
    pattern: re.Pattern[str]


def _rule(
    rule_id: str,
    category: DiagnosticCategory,
    description: str,
    pattern: str,
) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        category=category,
        description=description,
        pattern=re.compile(pattern, re.IGNORECASE),
    )


DETECTION_RULES: tuple[DetectionRule, ...] = (
    _rule(
        "AUTH-001",
        DiagnosticCategory.AUTHENTICATION,
        "Authentication failure indicator detected.",
        r"\b(?:authentication failed|invalid credentials|"
        r"login failed|invalid password)\b",
    ),
    _rule(
        "AUTH-002",
        DiagnosticCategory.AUTHENTICATION,
        "Authentication HTTP status indicator detected.",
        r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s+401|401\s+Unauthorized)\b",
    ),
    _rule(
        "AUTHZ-001",
        DiagnosticCategory.AUTHORIZATION,
        "Access or permission failure indicator detected.",
        r"\b(?:access denied|permission denied|"
        r"insufficient permissions|authorization failed)\b",
    ),
    _rule(
        "AUTHZ-002",
        DiagnosticCategory.AUTHORIZATION,
        "Authorization HTTP status indicator detected.",
        r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s+403|403\s+Forbidden)\b",
    ),
    _rule(
        "DB-001",
        DiagnosticCategory.DATABASE,
        "Database exception indicator detected.",
        r"\b(?:SQLException|SQLSTATE|OperationalError|"
        r"database error)\b",
    ),
    _rule(
        "DB-002",
        DiagnosticCategory.DATABASE,
        "Database connectivity indicator detected.",
        r"\b(?:database connection failed|"
        r"database unavailable|database connection refused)\b",
    ),
    _rule(
        "DB-003",
        DiagnosticCategory.DATABASE,
        "Database transaction contention indicator detected.",
        r"\b(?:deadlock detected|transaction deadlock|"
        r"lock wait timeout)\b",
    ),
    _rule(
        "NET-001",
        DiagnosticCategory.NETWORK,
        "Network connection failure indicator detected.",
        r"\b(?:connection refused|connection reset|"
        r"network unreachable|no route to host)\b",
    ),
    _rule(
        "NET-002",
        DiagnosticCategory.NETWORK,
        "Name resolution failure indicator detected.",
        r"\b(?:DNS resolution failed|"
        r"name resolution failed|host not found|NXDOMAIN)\b",
    ),
    _rule(
        "APP-001",
        DiagnosticCategory.APPLICATION,
        "Application exception indicator detected.",
        r"\b(?:NullPointerException|TypeError|"
        r"AttributeError|unhandled exception)\b",
    ),
    _rule(
        "APP-002",
        DiagnosticCategory.APPLICATION,
        "Internal application error indicator detected.",
        r"\b(?:internal server error|HTTP(?:/\d(?:\.\d)?)?\s+500|"
        r"application crashed)\b",
    ),
    _rule(
        "INT-001",
        DiagnosticCategory.INTEGRATION,
        "External integration failure indicator detected.",
        r"\b(?:webhook failed|integration failed|"
        r"upstream service unavailable|bad gateway|HTTP(?:/\d(?:\.\d)?)?\s+502)\b",
    ),
    _rule(
        "INT-002",
        DiagnosticCategory.INTEGRATION,
        "Ticketing workflow failure indicator detected.",
        r"\b(?:TK-ERR|ticketing failed|ticketing error)\b",
    ),
    _rule(
        "CFG-001",
        DiagnosticCategory.CONFIGURATION,
        "Application configuration failure indicator detected.",
        r"\b(?:invalid configuration|missing configuration|"
        r"configuration error|missing environment variable)\b",
    ),
    _rule(
        "PERF-001",
        DiagnosticCategory.PERFORMANCE,
        "Timeout indicator detected.",
        r"\b(?:request timed out|request timeout|"
        r"connection timeout|TimeoutException|"
        r"TimeoutError|gateway timeout|HTTP(?:/\d(?:\.\d)?)?\s+504)\b",
    ),
    _rule(
        "PERF-002",
        DiagnosticCategory.PERFORMANCE,
        "Application latency indicator detected.",
        r"\b(?:high latency|excessive latency|"
        r"slow query|response time exceeded)\b",
    ),
    _rule(
        "INFRA-001",
        DiagnosticCategory.INFRASTRUCTURE,
        "Memory resource exhaustion indicator detected.",
        r"\b(?:out of memory|OutOfMemoryError|"
        r"memory exhausted|OOMKilled)\b",
    ),
    _rule(
        "INFRA-002",
        DiagnosticCategory.INFRASTRUCTURE,
        "Storage resource exhaustion indicator detected.",
        r"\b(?:disk full|no space left on device|"
        r"disk quota exceeded)\b",
    ),
    _rule(
        "SEC-001",
        DiagnosticCategory.SECURITY,
        "Potential security-related indicator detected.",
        r"\b(?:SQL injection|invalid signature|"
        r"certificate verification failed|"
        r"unauthorized modification)\b",
    ),
    _rule(
        "DATA-001",
        DiagnosticCategory.DATA,
        "Data validation failure indicator detected.",
        r"\b(?:validation failed|schema validation failed|"
        r"invalid payload|malformed payload|"
        r"JSONDecodeError|invalid XML)\b",
    ),
)
