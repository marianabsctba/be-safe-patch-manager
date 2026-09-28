"""Add remediation project snapshots.

Revision ID: 0016_remediation_project_history
Revises: 0015_remediation_projects
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0016_remediation_project_history"
down_revision: Union[str, None] = "0015_remediation_projects"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediation_project_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("remediation_projects.id"), nullable=False),
        sa.Column("tracked_open_findings", sa.Integer(), nullable=False),
        sa.Column("current_scope_findings", sa.Integer(), nullable=False),
        sa.Column("current_assets", sa.Integer(), nullable=False),
        sa.Column("closed_from_baseline", sa.Integer(), nullable=False),
        sa.Column("new_findings_since_baseline", sa.Integer(), nullable=False),
        sa.Column("scope_departures", sa.Integer(), nullable=False),
        sa.Column("progress_percent", sa.Float(), nullable=False),
        sa.Column("pace_status", sa.String(32), nullable=False),
        sa.Column("source", sa.String(64), nullable=False, server_default="manual"),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_project_snapshots_project_id", "remediation_project_snapshots", ["project_id"])
    op.create_index("ix_remediation_project_snapshots_captured_at", "remediation_project_snapshots", ["captured_at"])


def downgrade() -> None:
    op.drop_index("ix_remediation_project_snapshots_captured_at", table_name="remediation_project_snapshots")
    op.drop_index("ix_remediation_project_snapshots_project_id", table_name="remediation_project_snapshots")
    op.drop_table("remediation_project_snapshots")
