"""Add asset risk profiles.

Revision ID: 0008_risk_profiles
Revises: 0007_risk_history
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_risk_profiles"
down_revision: Union[str, None] = "0007_risk_history"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_profiles",
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("criticality_override", sa.Integer(), nullable=True),
        sa.Column("external_override", sa.Boolean(), nullable=True),
        sa.Column("controls_json", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("agent_id"),
    )


def downgrade() -> None:
    op.drop_table("asset_risk_profiles")
