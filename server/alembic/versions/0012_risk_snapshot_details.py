"""Enrich asset risk snapshots.

Revision ID: 0012_risk_snapshot_details
Revises: 0011_risk_treatment
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012_risk_snapshot_details"
down_revision: Union[str, None] = "0011_risk_treatment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_risk_snapshots", sa.Column("model_version", sa.String(64), nullable=False, server_default="be_safe_asset_risk_v1"))
    op.add_column("asset_risk_snapshots", sa.Column("decomposition_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("asset_risk_snapshots", sa.Column("calculation_json", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("asset_risk_snapshots", sa.Column("risk_policy_json", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("asset_risk_snapshots", sa.Column("risk_appetite", sa.Integer(), nullable=False, server_default="700"))
    op.add_column("asset_risk_snapshots", sa.Column("governance_status", sa.String(64), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("asset_risk_snapshots", "governance_status")
    op.drop_column("asset_risk_snapshots", "risk_appetite")
    op.drop_column("asset_risk_snapshots", "risk_policy_json")
    op.drop_column("asset_risk_snapshots", "calculation_json")
    op.drop_column("asset_risk_snapshots", "decomposition_json")
    op.drop_column("asset_risk_snapshots", "model_version")
