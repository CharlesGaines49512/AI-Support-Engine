from enum import StrEnum


class LogFormat(StrEnum):
    """Supported application log formats."""

    XML = "xml"
    JSON = "json"
    TEXT = "text"


class LogSeverity(StrEnum):
    """Normalized application log severity."""

    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
