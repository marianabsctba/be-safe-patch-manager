"""Add campaign ring decision history.

Revision ID: 0029_campaign_ring_decisions
Revises: 0028_auto_patch_evaluations
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0029_campaign_ring_decisions"
down_revision: Union[str, None] = "0028_auto_patch_evaluations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "campaign_ring_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("from_ring", sa.Integer(), nullable=False),
        sa.Column("to_ring", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("health_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_campaign_ring_decisions_campaign_id", "campaign_ring_decisions", ["campaign_id"])
    op.create_index("ix_campaign_ring_decisions_decision", "campaign_ring_decisions", ["decision"])
    op.create_index("ix_campaign_ring_decisions_actor", "campaign_ring_decisions", ["actor"])
    op.create_index("ix_campaign_ring_decisions_created_at", "campaign_ring_decisions", ["created_at"])

def downgrade() -> None:
    op.drop_index("ix_campaign_ring_decisions_created_at", table_name="campaign_ring_decisions")
    op.drop_index("ix_campaign_ring_decisions_actor", table_name="campaign_ring_decisions")
    op.drop_index("ix_campaign_ring_decisions_decision", table_name="campaign_ring_decisions")
    op.drop_index("ix_campaign_ring_decisions_campaign_id", table_name="campaign_ring_decisions")
    op.drop_table("campaign_ring_decisions")
