from dataclasses import dataclass
from enum import StrEnum

from app.models.log_enums import LogSeverity


class DiagnosticCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    NETWORK = "network"
    APPLICATION = "application"
    INTEGRATION = "integration"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    DATA = "data"
    GENERAL = "general"


@dataclass(frozen=True, slots=True)
class DiagnosticFinding:
    """A deterministic diagnostic indicator associated with an event."""

    position: int
    category: DiagnosticCategory
    rule_id: str
    description: str
    severity: LogSeverity


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    """Diagnostic findings derived from sanitized log events."""

    entry_count: int
    findings: tuple[DiagnosticFinding, ...]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def affected_entry_count(self) -> int:
        return len({finding.position for finding in self.findings})

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)
