"""Add tag-based asset risk policies.

Revision ID: 0009_risk_policies
Revises: 0008_risk_profiles
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_risk_policies"
down_revision: Union[str, None] = "0008_risk_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_policies",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("target_tag", sa.String(128), nullable=False),
        sa.Column("risk_appetite", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_asset_risk_policies_name", "asset_risk_policies", ["name"], unique=True)
    op.create_index("ix_asset_risk_policies_target_tag", "asset_risk_policies", ["target_tag"])


def downgrade() -> None:
    op.drop_table("asset_risk_policies")
