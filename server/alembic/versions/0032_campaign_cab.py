"""Add CAB multi-approval decisions.

Revision ID: 0032_campaign_cab
Revises: 0031_tenant_locale
Create Date: 2026-09-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0032_campaign_cab"
down_revision: Union[str, None] = "0031_tenant_locale"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "campaign_approvals",
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "campaign_approvals",
        sa.Column("policy_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "campaign_approval_votes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["campaign_approvals.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("approval_id", "actor", name="uq_campaign_approval_vote_actor"),
    )
    op.create_index("ix_campaign_approval_votes_approval_id", "campaign_approval_votes", ["approval_id"])
    op.create_index("ix_campaign_approval_votes_campaign_id", "campaign_approval_votes", ["campaign_id"])
    op.create_index("ix_campaign_approval_votes_actor", "campaign_approval_votes", ["actor"])
    op.create_index("ix_campaign_approval_votes_decision", "campaign_approval_votes", ["decision"])
    op.create_index("ix_campaign_approval_votes_created_at", "campaign_approval_votes", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_campaign_approval_votes_created_at", table_name="campaign_approval_votes")
    op.drop_index("ix_campaign_approval_votes_decision", table_name="campaign_approval_votes")
    op.drop_index("ix_campaign_approval_votes_actor", table_name="campaign_approval_votes")
    op.drop_index("ix_campaign_approval_votes_campaign_id", table_name="campaign_approval_votes")
    op.drop_index("ix_campaign_approval_votes_approval_id", table_name="campaign_approval_votes")
    op.drop_table("campaign_approval_votes")
    op.drop_column("campaign_approvals", "policy_json")
    op.drop_column("campaign_approvals", "required_approvals")
