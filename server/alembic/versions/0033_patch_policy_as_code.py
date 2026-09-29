"""Add patch Policy-as-Code definitions.

Revision ID: 0033_patch_policy_as_code
Revises: 0032_campaign_cab
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0033_patch_policy_as_code"
down_revision: Union[str, None] = "0032_campaign_cab"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "patch_policy_definitions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("policy_json", sa.Text(), nullable=False),
        sa.Column("policy_sha256", sa.String(length=64), nullable=False),
        sa.Column("supersedes_id", sa.String(length=36), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["supersedes_id"], ["patch_policy_definitions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version", name="uq_patch_policy_name_version"),
    )
    op.create_index("ix_patch_policy_definitions_name", "patch_policy_definitions", ["name"])
    op.create_index("ix_patch_policy_definitions_enabled", "patch_policy_definitions", ["enabled"])
    op.create_index("ix_patch_policy_definitions_priority", "patch_policy_definitions", ["priority"])
    op.create_index("ix_patch_policy_definitions_policy_sha256", "patch_policy_definitions", ["policy_sha256"])
    op.create_index("ix_patch_policy_definitions_supersedes_id", "patch_policy_definitions", ["supersedes_id"])
    op.create_index("ix_patch_policy_definitions_created_at", "patch_policy_definitions", ["created_at"])

def downgrade() -> None:
    op.drop_index("ix_patch_policy_definitions_created_at", table_name="patch_policy_definitions")
    op.drop_index("ix_patch_policy_definitions_supersedes_id", table_name="patch_policy_definitions")
    op.drop_index("ix_patch_policy_definitions_policy_sha256", table_name="patch_policy_definitions")
    op.drop_index("ix_patch_policy_definitions_priority", table_name="patch_policy_definitions")
    op.drop_index("ix_patch_policy_definitions_enabled", table_name="patch_policy_definitions")
    op.drop_index("ix_patch_policy_definitions_name", table_name="patch_policy_definitions")
    op.drop_table("patch_policy_definitions")
