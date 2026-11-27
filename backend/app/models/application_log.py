from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base
from app.models.log_enums import LogFormat, LogSeverity


class LogSubmission(Base):
    """Metadata for a successfully ingested log submission."""

    __tablename__ = "log_submissions"

    __table_args__ = (
        CheckConstraint(
            "payload_bytes > 0",
            name="payload_bytes_positive",
        ),
        CheckConstraint(
            "entry_count > 0",
            name="entry_count_positive",
        ),
        CheckConstraint(
            "redaction_count >= 0",
            name="redaction_count_nonnegative",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid4,
    )

    incident_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    source_format: Mapped[LogFormat] = mapped_column(
        Enum(
            LogFormat,
            name="log_format",
            values_callable=lambda enum: [member.value for member in enum],
        ),
        nullable=False,
    )

    source_name: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    payload_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    entry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    redaction_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )


class LogEntry(Base):
    """Normalized and sanitized application log event."""

    __tablename__ = "log_entries"

    __table_args__ = (
        UniqueConstraint(
            "submission_id",
            "position",
        ),
        CheckConstraint(
            "position > 0",
            name="position_positive",
        ),
        CheckConstraint(
            "length(btrim(message)) > 0",
            name="message_nonempty",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid4,
    )

    submission_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey(
            "log_submissions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    position: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    severity: Mapped[LogSeverity] = mapped_column(
        Enum(
            LogSeverity,
            name="log_severity",
            values_callable=lambda enum: [member.value for member in enum],
        ),
        nullable=False,
        default=LogSeverity.UNKNOWN,
        index=True,
    )

    original_severity: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    service_name: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    exception: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    error_code: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    correlation_id: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )
