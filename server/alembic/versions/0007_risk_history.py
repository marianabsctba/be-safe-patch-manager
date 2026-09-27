"""Add asset risk history.

Revision ID: 0007_risk_history
Revises: 0006_sla_exceptions
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_risk_history"
down_revision: Union[str, None] = "0006_sla_exceptions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("level", sa.String(32), nullable=False),
        sa.Column("criticality", sa.Integer(), nullable=False),
        sa.Column("external", sa.Boolean(), nullable=False),
        sa.Column("open_findings", sa.Integer(), nullable=False),
        sa.Column("factors_json", sa.Text(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_risk_snapshots_agent_id", "asset_risk_snapshots", ["agent_id"])
    op.create_index("ix_asset_risk_snapshots_level", "asset_risk_snapshots", ["level"])
    op.create_index("ix_asset_risk_snapshots_captured_at", "asset_risk_snapshots", ["captured_at"])


def downgrade() -> None:
    op.drop_table("asset_risk_snapshots")
