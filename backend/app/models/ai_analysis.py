from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base
from app.models.ai_enums import AIAnalysisStatus


class AIAnalysis(Base):
    """Persist AI incident recommendations and execution metadata."""

    __tablename__ = "ai_analyses"

    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name="input_tokens_nonnegative",
        ),
        CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name="output_tokens_nonnegative",
        ),
        CheckConstraint(
            "total_tokens IS NULL OR total_tokens >= 0",
            name="total_tokens_nonnegative",
        ),
        CheckConstraint(
            "cached_input_tokens IS NULL OR cached_input_tokens >= 0",
            name="cached_tokens_nonnegative",
        ),
        CheckConstraint(
            "cached_input_tokens IS NULL OR input_tokens IS NULL "
            "OR cached_input_tokens <= input_tokens",
            name="cached_tokens_range",
        ),
        CheckConstraint(
            "total_tokens IS NULL OR input_tokens IS NULL "
            "OR output_tokens IS NULL "
            "OR total_tokens = input_tokens + output_tokens",
            name="token_total_consistency",
        ),
        CheckConstraint(
            "latency_ms IS NULL OR "
            "(latency_ms >= 0 AND latency_ms < 'Infinity'::float8)",
            name="latency_range",
        ),
        CheckConstraint(
            "estimated_cost_usd IS NULL OR "
            "(estimated_cost_usd >= 0 "
            "AND estimated_cost_usd < 'Infinity'::numeric)",
            name="cost_range",
        ),
        CheckConstraint(
            "redaction_count IS NULL OR redaction_count >= 0",
            name="redaction_count_nonnegative",
        ),
        CheckConstraint(
            "input_characters IS NULL OR input_characters > 0",
            name="input_characters_positive",
        ),
        CheckConstraint(
            "missing_information IS NULL OR "
            "jsonb_typeof(missing_information) = 'array'",
            name="missing_information_array",
        ),
        CheckConstraint(
            "(status = 'succeeded' "
            "AND suggested_category IS NOT NULL "
            "AND recommended_severity IS NOT NULL "
            "AND summary IS NOT NULL "
            "AND justification IS NOT NULL "
            "AND confidence IS NOT NULL "
            "AND insufficient_evidence IS NOT NULL "
            "AND missing_information IS NOT NULL "
            "AND redaction_count IS NOT NULL "
            "AND input_characters IS NOT NULL "
            "AND latency_ms IS NOT NULL "
            "AND error_code IS NULL "
            "AND error_message IS NULL) "
            "OR "
            "(status = 'failed' "
            "AND error_code IS NOT NULL "
            "AND error_message IS NOT NULL "
            "AND suggested_category IS NULL "
            "AND recommended_priority IS NULL "
            "AND recommended_severity IS NULL "
            "AND summary IS NULL "
            "AND justification IS NULL "
            "AND confidence IS NULL "
            "AND insufficient_evidence IS NULL "
            "AND missing_information IS NULL)",
            name="execution_status_consistency",
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

    status: Mapped[AIAnalysisStatus] = mapped_column(
        Enum(
            AIAnalysisStatus,
            name="ai_analysis_status",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )

    suggested_category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    recommended_priority: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    recommended_severity: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    justification: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    insufficient_evidence: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    missing_information: Mapped[list[str] | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    model: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    prompt_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    request_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    input_tokens: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    output_tokens: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    total_tokens: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    cached_input_tokens: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    estimated_cost_usd: Mapped[Decimal | None] = mapped_column(
        Numeric(18, 10),
        nullable=True,
    )

    latency_ms: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    redaction_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    input_characters: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    error_code: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
