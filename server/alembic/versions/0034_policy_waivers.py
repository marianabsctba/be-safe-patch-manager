"""Add policy waivers.

Revision ID: 0034_policy_waivers
Revises: 0033_patch_policy_as_code
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0034_policy_waivers"
down_revision: Union[str, None] = "0033_patch_policy_as_code"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "patch_policy_waivers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("policy_sha256", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("revoke_reason", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["patch_policy_definitions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, cols in (
        ("ix_patch_policy_waivers_campaign_id", ["campaign_id"]),
        ("ix_patch_policy_waivers_policy_id", ["policy_id"]),
        ("ix_patch_policy_waivers_policy_sha256", ["policy_sha256"]),
        ("ix_patch_policy_waivers_expires_at", ["expires_at"]),
        ("ix_patch_policy_waivers_created_at", ["created_at"]),
        ("ix_patch_policy_waivers_revoked_at", ["revoked_at"]),
    ):
        op.create_index(name, "patch_policy_waivers", cols)

def downgrade() -> None:
    for name in (
        "ix_patch_policy_waivers_revoked_at",
        "ix_patch_policy_waivers_created_at",
        "ix_patch_policy_waivers_expires_at",
        "ix_patch_policy_waivers_policy_sha256",
        "ix_patch_policy_waivers_policy_id",
        "ix_patch_policy_waivers_campaign_id",
    ):
        op.drop_index(name, table_name="patch_policy_waivers")
    op.drop_table("patch_policy_waivers")
