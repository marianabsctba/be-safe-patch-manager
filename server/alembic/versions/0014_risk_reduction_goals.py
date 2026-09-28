"""Add risk reduction goals.

Revision ID: 0014_risk_reduction_goals
Revises: 0013_asset_accountability
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0014_risk_reduction_goals"
down_revision: Union[str, None] = "0013_asset_accountability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_reduction_goals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("scope_tag", sa.String(128), nullable=False, server_default=""),
        sa.Column("goal_type", sa.String(64), nullable=False),
        sa.Column("target_value", sa.Float(), nullable=False),
        sa.Column("baseline_value", sa.Float(), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_risk_reduction_goals_name", "risk_reduction_goals", ["name"], unique=True)
    op.create_index("ix_risk_reduction_goals_scope_tag", "risk_reduction_goals", ["scope_tag"])
    op.create_index("ix_risk_reduction_goals_goal_type", "risk_reduction_goals", ["goal_type"])
    op.create_index("ix_risk_reduction_goals_due_at", "risk_reduction_goals", ["due_at"])
    op.create_index("ix_risk_reduction_goals_status", "risk_reduction_goals", ["status"])


def downgrade() -> None:
    op.drop_index("ix_risk_reduction_goals_status", table_name="risk_reduction_goals")
    op.drop_index("ix_risk_reduction_goals_due_at", table_name="risk_reduction_goals")
    op.drop_index("ix_risk_reduction_goals_goal_type", table_name="risk_reduction_goals")
    op.drop_index("ix_risk_reduction_goals_scope_tag", table_name="risk_reduction_goals")
    op.drop_index("ix_risk_reduction_goals_name", table_name="risk_reduction_goals")
    op.drop_table("risk_reduction_goals")
