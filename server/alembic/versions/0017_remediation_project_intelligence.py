"""Enrich remediation project intelligence history.

Revision ID: 0017_project_intel
Revises: 0016_remediation_project_history
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0017_project_intel"
down_revision: Union[str, None] = "0016_remediation_project_history"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("remediation_project_snapshots", sa.Column("remaining_risk_reduction", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("realized_risk_reduction", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("risk_reduction_progress_percent", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("expected_progress_percent", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("schedule_variance_percent", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("sla_breached", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("kev_findings", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("external_assets", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("average_age_days", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("oldest_age_days", sa.Float(), nullable=False, server_default="0"))
    op.add_column("remediation_project_snapshots", sa.Column("attention_status", sa.String(32), nullable=False, server_default="on_track"))


def downgrade() -> None:
    op.drop_column("remediation_project_snapshots", "attention_status")
    op.drop_column("remediation_project_snapshots", "oldest_age_days")
    op.drop_column("remediation_project_snapshots", "average_age_days")
    op.drop_column("remediation_project_snapshots", "external_assets")
    op.drop_column("remediation_project_snapshots", "kev_findings")
    op.drop_column("remediation_project_snapshots", "sla_breached")
    op.drop_column("remediation_project_snapshots", "schedule_variance_percent")
    op.drop_column("remediation_project_snapshots", "expected_progress_percent")
    op.drop_column("remediation_project_snapshots", "risk_reduction_progress_percent")
    op.drop_column("remediation_project_snapshots", "realized_risk_reduction")
    op.drop_column("remediation_project_snapshots", "remaining_risk_reduction")
