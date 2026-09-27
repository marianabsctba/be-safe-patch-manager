"""Add job leases and attempt tracking.

Revision ID: 0002_job_leases
Revises: 0001_initial
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_job_leases"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("patch_jobs", sa.Column("claim_token_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("patch_jobs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("patch_jobs", sa.Column("last_lease_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("patch_jobs", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_patch_jobs_status", "patch_jobs", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_patch_jobs_status", table_name="patch_jobs")
    op.drop_column("patch_jobs", "attempt_count")
    op.drop_column("patch_jobs", "last_lease_at")
    op.drop_column("patch_jobs", "lease_expires_at")
    op.drop_column("patch_jobs", "claim_token_hash")
