import re

from app.logs.detection_rules import DETECTION_RULES
from app.logs.evidence_contracts import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
)
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.models.log_enums import LogSeverity

NEGATED_INDICATOR = re.compile(
    r"\b(?:no evidence of|no signs of|no indication of|"
    r"no instance of|not experiencing|"
    r"no)[ \t]+$",
    re.IGNORECASE,
)


def _contains_indicator(
    pattern: re.Pattern[str],
    value: str,
) -> bool:
    """Recognize indicators without matching explicit local negation."""

    for match in pattern.finditer(value):
        prefix = value[max(0, match.start() - 64) : match.start()]

        if NEGATED_INDICATOR.search(prefix) is None:
            return True

    return False


class DiagnosticDetector:
    """Identify deterministic indicators in sanitized log records."""

    def detect_entry(
        self,
        entry: SanitizedLogEntry,
    ) -> tuple[DiagnosticFinding, ...]:
        findings: list[DiagnosticFinding] = []

        searchable_fields = (
            entry.message,
            entry.exception or "",
            entry.error_code or "",
        )

        for rule in DETECTION_RULES:
            if any(
                _contains_indicator(rule.pattern, value) for value in searchable_fields
            ):
                findings.append(
                    DiagnosticFinding(
                        position=entry.position,
                        category=rule.category,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=entry.severity,
                    )
                )

        if entry.severity in {
            LogSeverity.ERROR,
            LogSeverity.CRITICAL,
        }:
            findings.append(
                DiagnosticFinding(
                    position=entry.position,
                    category=DiagnosticCategory.GENERAL,
                    rule_id="SEV-001",
                    description=("Explicit error-level log severity detected."),
                    severity=entry.severity,
                )
            )

        return tuple(findings)

    def detect(
        self,
        log: SanitizedLog,
    ) -> DiagnosticReport:
        findings = tuple(
            finding for entry in log.entries for finding in self.detect_entry(entry)
        )

        return DiagnosticReport(
            entry_count=log.entry_count,
            findings=findings,
        )
