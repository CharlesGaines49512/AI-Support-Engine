from enum import StrEnum


class AIAnalysisStatus(StrEnum):
    """Execution status of an AI incident analysis."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
