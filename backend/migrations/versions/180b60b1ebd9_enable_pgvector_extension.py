"""enable pgvector extension

Revision ID: 180b60b1ebd9
Revises:
Create Date: 2026-11-24 09:42:16.878402

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "180b60b1ebd9"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Enable the pgvector extension."""
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")


def downgrade() -> None:
    """Remove the pgvector extension."""
    op.execute("DROP EXTENSION IF EXISTS vector")
