"""Add patch change freeze windows and campaign overrides.

Revision ID: 0025_change_freeze
Revises: 0024_patch_feed_providers
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0025_change_freeze"
down_revision: Union[str, None] = "0024_patch_feed_providers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "patch_freeze_windows",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("target_os", sa.String(length=32), nullable=False, server_default="all"),
        sa.Column("target_tag", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_patch_freeze_windows_name","patch_freeze_windows",["name"],unique=True)
    op.create_index("ix_patch_freeze_windows_target_os","patch_freeze_windows",["target_os"])
    op.create_index("ix_patch_freeze_windows_target_tag","patch_freeze_windows",["target_tag"])
    op.create_index("ix_patch_freeze_windows_starts_at","patch_freeze_windows",["starts_at"])
    op.create_index("ix_patch_freeze_windows_ends_at","patch_freeze_windows",["ends_at"])
    op.create_index("ix_patch_freeze_windows_enabled","patch_freeze_windows",["enabled"])

    op.create_table(
        "campaign_freeze_overrides",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["campaign_id"],["campaigns.id"],ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_id"),
    )
    op.create_index("ix_campaign_freeze_overrides_campaign_id","campaign_freeze_overrides",["campaign_id"],unique=True)

def downgrade() -> None:
    op.drop_index("ix_campaign_freeze_overrides_campaign_id",table_name="campaign_freeze_overrides")
    op.drop_table("campaign_freeze_overrides")
    op.drop_index("ix_patch_freeze_windows_enabled",table_name="patch_freeze_windows")
    op.drop_index("ix_patch_freeze_windows_ends_at",table_name="patch_freeze_windows")
    op.drop_index("ix_patch_freeze_windows_starts_at",table_name="patch_freeze_windows")
    op.drop_index("ix_patch_freeze_windows_target_tag",table_name="patch_freeze_windows")
    op.drop_index("ix_patch_freeze_windows_target_os",table_name="patch_freeze_windows")
    op.drop_index("ix_patch_freeze_windows_name",table_name="patch_freeze_windows")
    op.drop_table("patch_freeze_windows")
