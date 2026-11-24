from enum import StrEnum


class IncidentStatus(StrEnum):
    """Supported incident lifecycle statuses."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentPriority(StrEnum):
    """Supported incident priority levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
