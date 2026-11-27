from app.core.exceptions import ApplicationError


class LogSubmissionNotFoundError(ApplicationError):
    """The requested submission does not exist in the incident."""

    def __init__(self) -> None:
        super().__init__("Application log submission was not found.")


class LogEntryNotFoundError(ApplicationError):
    """The requested event does not exist in the submission."""

    def __init__(self) -> None:
        super().__init__("Application log entry was not found.")


class InvalidLogPaginationError(ApplicationError):
    """The requested pagination parameters are invalid."""

    def __init__(self) -> None:
        super().__init__(
            "Offset must be a nonnegative 64-bit integer; "
            "limit must be an integer from 1 to 100."
        )


class LogPersistenceIntegrityError(ApplicationError):
    """Persisted records do not match submission accounting."""

    def __init__(self) -> None:
        super().__init__("Persisted application log integrity verification failed.")
