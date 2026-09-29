"""Add immutable campaign preflight snapshots.

Revision ID: 0030_campaign_preflight
Revises: 0029_campaign_ring_decisions
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0030_campaign_preflight"
down_revision: Union[str, None] = "0029_campaign_ring_decisions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaign_preflight_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("readiness", sa.String(length=32), nullable=False),
        sa.Column("deploy_allowed", sa.Boolean(), nullable=False),
        sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("result_sha256", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_campaign_preflight_snapshots_campaign_id", "campaign_preflight_snapshots", ["campaign_id"])
    op.create_index("ix_campaign_preflight_snapshots_readiness", "campaign_preflight_snapshots", ["readiness"])
    op.create_index("ix_campaign_preflight_snapshots_actor", "campaign_preflight_snapshots", ["actor"])
    op.create_index("ix_campaign_preflight_snapshots_created_at", "campaign_preflight_snapshots", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_campaign_preflight_snapshots_created_at", table_name="campaign_preflight_snapshots")
    op.drop_index("ix_campaign_preflight_snapshots_actor", table_name="campaign_preflight_snapshots")
    op.drop_index("ix_campaign_preflight_snapshots_readiness", table_name="campaign_preflight_snapshots")
    op.drop_index("ix_campaign_preflight_snapshots_campaign_id", table_name="campaign_preflight_snapshots")
    op.drop_table("campaign_preflight_snapshots")
