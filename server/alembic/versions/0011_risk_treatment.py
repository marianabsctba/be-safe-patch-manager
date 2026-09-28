"""Add asset risk treatment plans.

Revision ID: 0011_risk_treatment
Revises: 0010_risk_accept
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011_risk_treatment"
down_revision: Union[str, None] = "0010_risk_accept"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_treatments",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("completion_evidence", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_risk_treatments_agent_id", "asset_risk_treatments", ["agent_id"])
    op.create_index("ix_asset_risk_treatments_due_at", "asset_risk_treatments", ["due_at"])
    op.create_index("ix_asset_risk_treatments_status", "asset_risk_treatments", ["status"])


def downgrade() -> None:
    op.drop_table("asset_risk_treatments")
