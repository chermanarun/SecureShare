"""add authz repair jobs

Revision ID: 0002_authz_repair_jobs
Revises: 0001_initial
Create Date: 2026-06-29
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_authz_repair_jobs"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authz_repair_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("user", sa.String(length=240), nullable=False),
        sa.Column("relation", sa.String(length=80), nullable=False),
        sa.Column("object", sa.String(length=240), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_authz_repair_jobs_status"), "authz_repair_jobs", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_authz_repair_jobs_status"), table_name="authz_repair_jobs")
    op.drop_table("authz_repair_jobs")
