from types import MappingProxyType

from app.models.log_enums import LogSeverity

SEVERITY_ALIASES = MappingProxyType(
    {
        "trace": LogSeverity.TRACE,
        "verbose": LogSeverity.TRACE,
        "debug": LogSeverity.DEBUG,
        "info": LogSeverity.INFO,
        "information": LogSeverity.INFO,
        "informational": LogSeverity.INFO,
        "notice": LogSeverity.INFO,
        "warn": LogSeverity.WARNING,
        "warning": LogSeverity.WARNING,
        "error": LogSeverity.ERROR,
        "err": LogSeverity.ERROR,
        "severe": LogSeverity.ERROR,
        "critical": LogSeverity.CRITICAL,
        "crit": LogSeverity.CRITICAL,
        "fatal": LogSeverity.CRITICAL,
        "alert": LogSeverity.CRITICAL,
        "emerg": LogSeverity.CRITICAL,
        "emergency": LogSeverity.CRITICAL,
        "panic": LogSeverity.CRITICAL,
        "unknown": LogSeverity.UNKNOWN,
    }
)


def normalize_severity(
    severity: str | None,
) -> LogSeverity:
    """Map an original severity label to a canonical value."""

    if severity is None:
        return LogSeverity.UNKNOWN

    return SEVERITY_ALIASES.get(
        severity.strip().casefold(),
        LogSeverity.UNKNOWN,
    )
