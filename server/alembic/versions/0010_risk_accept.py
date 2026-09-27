"""Add asset risk acceptances.

Revision ID: 0010_risk_accept
Revises: 0009_risk_policies
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_risk_accept"
down_revision: Union[str, None] = "0009_risk_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_acceptances",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=False),
        sa.Column("revoke_reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_risk_acceptances_agent_id", "asset_risk_acceptances", ["agent_id"])
    op.create_index("ix_asset_risk_acceptances_expires_at", "asset_risk_acceptances", ["expires_at"])


def downgrade() -> None:
    op.drop_table("asset_risk_acceptances")
