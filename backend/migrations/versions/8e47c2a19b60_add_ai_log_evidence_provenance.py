"""Add AI application log evidence provenance.

Revision ID: 8e47c2a19b60
Revises: c150a35f0639
"""

import sqlalchemy as sa
from alembic import op

revision = "8e47c2a19b60"
down_revision = "c150a35f0639"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_analyses",
        sa.Column(
            "log_submission_id",
            sa.Uuid(),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "log_evidence_version",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "log_evidence_sha256",
            sa.String(length=64),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "log_evidence_event_count",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_ai_analyses_log_submission_id",
        "ai_analyses",
        ["log_submission_id"],
        unique=False,
    )

    op.create_check_constraint(
        op.f("ck_ai_analyses_log_evidence_consistency"),
        "ai_analyses",
        "(log_submission_id IS NULL "
        "AND log_evidence_version IS NULL "
        "AND log_evidence_sha256 IS NULL "
        "AND log_evidence_event_count IS NULL) "
        "OR "
        "(log_submission_id IS NOT NULL "
        "AND log_evidence_version IS NOT NULL "
        "AND length(btrim(log_evidence_version)) > 0 "
        "AND log_evidence_sha256 IS NOT NULL "
        "AND log_evidence_sha256 ~ '^[0-9a-f]{64}$' "
        "AND log_evidence_event_count IS NOT NULL "
        "AND log_evidence_event_count BETWEEN 0 AND 100)",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_ai_analyses_log_evidence_consistency"),
        "ai_analyses",
        type_="check",
    )

    op.drop_index(
        "ix_ai_analyses_log_submission_id",
        table_name="ai_analyses",
    )

    op.drop_column(
        "ai_analyses",
        "log_evidence_event_count",
    )

    op.drop_column(
        "ai_analyses",
        "log_evidence_sha256",
    )

    op.drop_column(
        "ai_analyses",
        "log_evidence_version",
    )

    op.drop_column(
        "ai_analyses",
        "log_submission_id",
    )
