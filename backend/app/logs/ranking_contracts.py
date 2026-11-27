from dataclasses import dataclass

from app.logs.evidence_contracts import DiagnosticFinding


@dataclass(frozen=True, slots=True)
class RankedFinding:
    """Diagnostic finding with deterministic relevance scoring."""

    finding: DiagnosticFinding
    score: int
    severity_score: int
    specificity_score: int
    category_score: int
    recurrence_score: int
    occurrence_count: int


@dataclass(frozen=True, slots=True)
class RankedDiagnosticReport:
    """Diagnostic findings ordered by their evidence relevance."""

    entry_count: int
    findings: tuple[RankedFinding, ...]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def affected_entry_count(self) -> int:
        return len({ranked.finding.position for ranked in self.findings})

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)
