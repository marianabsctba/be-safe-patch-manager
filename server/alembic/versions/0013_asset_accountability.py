"""Add asset accountability context.

Revision ID: 0013_asset_accountability
Revises: 0012_risk_snapshot_details
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013_asset_accountability"
down_revision: Union[str, None] = "0012_risk_snapshot_details"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_risk_profiles", sa.Column("owner", sa.String(255), nullable=False, server_default=""))
    op.add_column("asset_risk_profiles", sa.Column("business_service", sa.String(255), nullable=False, server_default=""))
    op.add_column("asset_risk_profiles", sa.Column("environment", sa.String(64), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("asset_risk_profiles", "environment")
    op.drop_column("asset_risk_profiles", "business_service")
    op.drop_column("asset_risk_profiles", "owner")
