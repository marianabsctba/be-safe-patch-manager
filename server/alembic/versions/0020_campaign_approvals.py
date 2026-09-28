"""Add campaign approval gate.

Revision ID: 0020_campaign_approvals
Revises: 0019_patch_block_rules
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0020_campaign_approvals"
down_revision: Union[str, None] = "0019_patch_block_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaign_approvals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("request_reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("decision_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_id"),
    )
    op.create_index("ix_campaign_approvals_campaign_id", "campaign_approvals", ["campaign_id"])
    op.create_index("ix_campaign_approvals_status", "campaign_approvals", ["status"])
    op.create_index("ix_campaign_approvals_requested_by", "campaign_approvals", ["requested_by"])


def downgrade() -> None:
    op.drop_index("ix_campaign_approvals_requested_by", table_name="campaign_approvals")
    op.drop_index("ix_campaign_approvals_status", table_name="campaign_approvals")
    op.drop_index("ix_campaign_approvals_campaign_id", table_name="campaign_approvals")
    op.drop_table("campaign_approvals")
