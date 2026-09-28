"""Add patch block rules.

Revision ID: 0019_patch_block_rules
Revises: 0018_project_scope
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0019_patch_block_rules"
down_revision: Union[str, None] = "0018_project_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_block_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("patch_ref", sa.String(length=255), nullable=False),
        sa.Column("target_os", sa.String(length=32), nullable=False, server_default="all"),
        sa.Column("target_tag", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_patch_block_rules_name", "patch_block_rules", ["name"])
    op.create_index("ix_patch_block_rules_patch_ref", "patch_block_rules", ["patch_ref"])
    op.create_index("ix_patch_block_rules_target_os", "patch_block_rules", ["target_os"])
    op.create_index("ix_patch_block_rules_target_tag", "patch_block_rules", ["target_tag"])
    op.create_index("ix_patch_block_rules_enabled", "patch_block_rules", ["enabled"])
    op.create_index("ix_patch_block_rules_expires_at", "patch_block_rules", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_patch_block_rules_expires_at", table_name="patch_block_rules")
    op.drop_index("ix_patch_block_rules_enabled", table_name="patch_block_rules")
    op.drop_index("ix_patch_block_rules_target_tag", table_name="patch_block_rules")
    op.drop_index("ix_patch_block_rules_target_os", table_name="patch_block_rules")
    op.drop_index("ix_patch_block_rules_patch_ref", table_name="patch_block_rules")
    op.drop_index("ix_patch_block_rules_name", table_name="patch_block_rules")
    op.drop_table("patch_block_rules")
