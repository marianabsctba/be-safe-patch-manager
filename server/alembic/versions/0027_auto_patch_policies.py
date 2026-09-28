"""Add auto patch policies.

Revision ID: 0027_auto_patch_policies
Revises: 0026_patch_feed_adapter_state
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0027_auto_patch_policies"
down_revision: Union[str, None] = "0026_patch_feed_adapter_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "auto_patch_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("mode", sa.String(length=32), nullable=False, server_default="recommend"),
        sa.Column("target_os", sa.String(length=32), nullable=False, server_default="all"),
        sa.Column("target_tag", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("require_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("require_external", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("require_patch_tuesday", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("min_missing_assets", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("confidence_floor", sa.String(length=32), nullable=False, server_default="insufficient_data"),
        sa.Column("allow_eol", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("superseded_action", sa.String(length=32), nullable=False, server_default="replace"),
        sa.Column("ring_percent", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("require_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_health_gate", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_rollback", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_auto_patch_policies_name", "auto_patch_policies", ["name"], unique=True)
    op.create_index("ix_auto_patch_policies_enabled", "auto_patch_policies", ["enabled"])
    op.create_index("ix_auto_patch_policies_mode", "auto_patch_policies", ["mode"])
    op.create_index("ix_auto_patch_policies_target_os", "auto_patch_policies", ["target_os"])
    op.create_index("ix_auto_patch_policies_target_tag", "auto_patch_policies", ["target_tag"])

def downgrade() -> None:
    op.drop_index("ix_auto_patch_policies_target_tag", table_name="auto_patch_policies")
    op.drop_index("ix_auto_patch_policies_target_os", table_name="auto_patch_policies")
    op.drop_index("ix_auto_patch_policies_mode", table_name="auto_patch_policies")
    op.drop_index("ix_auto_patch_policies_enabled", table_name="auto_patch_policies")
    op.drop_index("ix_auto_patch_policies_name", table_name="auto_patch_policies")
    op.drop_table("auto_patch_policies")
