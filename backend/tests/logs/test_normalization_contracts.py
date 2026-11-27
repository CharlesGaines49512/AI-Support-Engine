from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.models.log_enums import LogFormat, LogSeverity


def test_normalized_entry_required_fields() -> None:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message="Synthetic application failure.",
    )

    assert entry.position == 1
    assert entry.severity == LogSeverity.ERROR
    assert entry.message == "Synthetic application failure."


def test_normalized_entry_optional_defaults() -> None:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.UNKNOWN,
        message="Synthetic event.",
    )

    assert entry.event_timestamp is None
    assert entry.original_severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_complete_normalized_entry() -> None:
    timestamp = datetime(
        2026,
        11,
        24,
        15,
        30,
        tzinfo=UTC,
    )

    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.CRITICAL,
        message="Synthetic ticketing failure.",
        event_timestamp=timestamp,
        original_severity="FATAL",
        service_name="ticketing",
        exception="ConnectionTimeoutException",
        error_code="TK-ERR",
        correlation_id="TXN-123",
    )

    assert entry.position == 1
    assert entry.severity == LogSeverity.CRITICAL
    assert entry.message == "Synthetic ticketing failure."
    assert entry.event_timestamp == timestamp
    assert entry.original_severity == "FATAL"
    assert entry.service_name == "ticketing"
    assert entry.exception == "ConnectionTimeoutException"
    assert entry.error_code == "TK-ERR"
    assert entry.correlation_id == "TXN-123"


def test_normalized_entry_is_immutable() -> None:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.INFO,
        message="Synthetic event.",
    )

    with pytest.raises(FrozenInstanceError):
        type(entry).__setattr__(entry, "message", "Modified")


def test_normalized_log_is_immutable() -> None:
    result = NormalizedLog(
        source_format=LogFormat.XML,
        payload_bytes=100,
        entries=(),
    )

    with pytest.raises(FrozenInstanceError):
        type(result).__setattr__(result, "payload_bytes", 200)


@pytest.mark.parametrize(
    "source_format",
    list(LogFormat),
)
def test_normalized_log_source_format(
    source_format: LogFormat,
) -> None:
    result = NormalizedLog(
        source_format=source_format,
        payload_bytes=100,
        entries=(),
    )

    assert result.source_format == source_format
    assert result.payload_bytes == 100


@pytest.mark.parametrize(
    "entry_count",
    [0, 1, 2, 10, 100],
)
def test_entry_count_is_derived(
    entry_count: int,
) -> None:
    entries = tuple(
        NormalizedLogEntry(
            position=position,
            severity=LogSeverity.INFO,
            message="Synthetic event.",
        )
        for position in range(1, entry_count + 1)
    )

    result = NormalizedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=entries,
    )

    assert result.entry_count == entry_count
    assert result.entries == entries


def test_entry_order_preserved() -> None:
    entries = (
        NormalizedLogEntry(
            position=1,
            severity=LogSeverity.INFO,
            message="First",
        ),
        NormalizedLogEntry(
            position=2,
            severity=LogSeverity.ERROR,
            message="Second",
        ),
        NormalizedLogEntry(
            position=3,
            severity=LogSeverity.WARNING,
            message="Third",
        ),
    )

    result = NormalizedLog(
        source_format=LogFormat.TEXT,
        payload_bytes=100,
        entries=entries,
    )

    assert [entry.position for entry in result.entries] == [1, 2, 3]

    assert [entry.message for entry in result.entries] == ["First", "Second", "Third"]


def test_original_severity_preserved() -> None:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.UNKNOWN,
        original_severity="VENDOR_SPECIFIC_LEVEL",
        message="Synthetic diagnostic message.",
    )

    assert entry.severity == LogSeverity.UNKNOWN
    assert entry.original_severity == "VENDOR_SPECIFIC_LEVEL"
