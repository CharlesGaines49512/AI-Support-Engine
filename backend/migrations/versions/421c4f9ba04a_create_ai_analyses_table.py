"""create ai analyses table

Revision ID: 421c4f9ba04a
Revises: 14a739ac0e2f
Create Date: 2026-11-24 15:59:54.030599
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "421c4f9ba04a"
down_revision: str | Sequence[str] | None = "14a739ac0e2f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the AI analysis table and supporting indexes."""
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "succeeded",
                "failed",
                name="ai_analysis_status",
            ),
            nullable=False,
        ),
        sa.Column(
            "suggested_category",
            sa.String(length=100),
            nullable=True,
        ),
        sa.Column(
            "recommended_priority",
            sa.String(length=20),
            nullable=True,
        ),
        sa.Column(
            "recommended_severity",
            sa.String(length=20),
            nullable=True,
        ),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "insufficient_evidence",
            sa.Boolean(),
            nullable=True,
        ),
        sa.Column(
            "missing_information",
            postgresql.JSONB(none_as_null=True),
            nullable=True,
        ),
        sa.Column(
            "provider",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "model",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "prompt_version",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "request_id",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("total_tokens", sa.Integer(), nullable=True),
        sa.Column(
            "cached_input_tokens",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "estimated_cost_usd",
            sa.Numeric(precision=18, scale=10),
            nullable=True,
        ),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("redaction_count", sa.Integer(), nullable=True),
        sa.Column("input_characters", sa.Integer(), nullable=True),
        sa.Column(
            "error_code",
            sa.String(length=100),
            nullable=True,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name=op.f("ck_ai_analyses_confidence_range"),
        ),
        sa.CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name=op.f("ck_ai_analyses_input_tokens_nonnegative"),
        ),
        sa.CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name=op.f("ck_ai_analyses_output_tokens_nonnegative"),
        ),
        sa.CheckConstraint(
            "total_tokens IS NULL OR total_tokens >= 0",
            name=op.f("ck_ai_analyses_total_tokens_nonnegative"),
        ),
        sa.CheckConstraint(
            "cached_input_tokens IS NULL OR cached_input_tokens >= 0",
            name=op.f("ck_ai_analyses_cached_tokens_nonnegative"),
        ),
        sa.CheckConstraint(
            "cached_input_tokens IS NULL OR input_tokens IS NULL "
            "OR cached_input_tokens <= input_tokens",
            name=op.f("ck_ai_analyses_cached_tokens_range"),
        ),
        sa.CheckConstraint(
            "total_tokens IS NULL OR input_tokens IS NULL "
            "OR output_tokens IS NULL "
            "OR total_tokens = input_tokens + output_tokens",
            name=op.f("ck_ai_analyses_token_total_consistency"),
        ),
        sa.CheckConstraint(
            "latency_ms IS NULL OR "
            "(latency_ms >= 0 AND latency_ms < 'Infinity'::float8)",
            name=op.f("ck_ai_analyses_latency_range"),
        ),
        sa.CheckConstraint(
            "estimated_cost_usd IS NULL OR "
            "(estimated_cost_usd >= 0 "
            "AND estimated_cost_usd < 'Infinity'::numeric)",
            name=op.f("ck_ai_analyses_cost_range"),
        ),
        sa.CheckConstraint(
            "redaction_count IS NULL OR redaction_count >= 0",
            name=op.f("ck_ai_analyses_redaction_count_nonnegative"),
        ),
        sa.CheckConstraint(
            "input_characters IS NULL OR input_characters > 0",
            name=op.f("ck_ai_analyses_input_characters_positive"),
        ),
        sa.CheckConstraint(
            "missing_information IS NULL OR "
            "jsonb_typeof(missing_information) = 'array'",
            name=op.f("ck_ai_analyses_missing_information_array"),
        ),
        sa.CheckConstraint(
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
            name=op.f("ck_ai_analyses_execution_status_consistency"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_ai_analyses_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_ai_analyses"),
        ),
    )

    op.create_index(
        op.f("ix_ai_analyses_created_at"),
        "ai_analyses",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        op.f("ix_ai_analyses_incident_id"),
        "ai_analyses",
        ["incident_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_ai_analyses_status"),
        "ai_analyses",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the AI analysis table and associated enum."""
    op.drop_index(
        op.f("ix_ai_analyses_status"),
        table_name="ai_analyses",
    )

    op.drop_index(
        op.f("ix_ai_analyses_incident_id"),
        table_name="ai_analyses",
    )

    op.drop_index(
        op.f("ix_ai_analyses_created_at"),
        table_name="ai_analyses",
    )

    op.drop_table("ai_analyses")

    op.execute("DROP TYPE IF EXISTS ai_analysis_status")
