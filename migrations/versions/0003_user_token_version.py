"""add user token version

Revision ID: 0003_user_token_version
Revises: 0002_authz_repair_jobs
Create Date: 2026-07-01
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_user_token_version"
down_revision = "0002_authz_repair_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    op.alter_column("users", "token_version", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "token_version")
