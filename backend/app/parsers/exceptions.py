from app.core.exceptions import ApplicationError


class LogParsingError(ApplicationError):
    """Base exception for rejected log submissions."""


class InvalidLogPayloadError(LogParsingError):
    """The submitted payload is empty or invalid."""


class LogPayloadTooLargeError(LogParsingError):
    """The submitted payload exceeds its configured size limit."""


class InvalidLogEncodingError(LogParsingError):
    """The submitted payload is not supported UTF-8 text."""


class MalformedLogError(LogParsingError):
    """The submitted log does not match its declared format."""


class UnsafeLogContentError(LogParsingError):
    """The submitted log contains unsupported unsafe constructs."""


class LogResourceLimitError(LogParsingError):
    """Parsing would exceed a configured resource limit."""
