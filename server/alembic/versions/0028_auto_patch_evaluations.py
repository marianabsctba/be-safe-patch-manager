"""Add auto patch evaluation ledger.

Revision ID: 0028_auto_patch_evaluations
Revises: 0027_auto_patch_policies
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0028_auto_patch_evaluations"
down_revision: Union[str, None] = "0027_auto_patch_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "auto_patch_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("create_drafts", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("policies", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("decisions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("drafts_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("holds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ready", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auto_patch_evaluations_actor", "auto_patch_evaluations", ["actor"])
    op.create_index("ix_auto_patch_evaluations_create_drafts", "auto_patch_evaluations", ["create_drafts"])
    op.create_index("ix_auto_patch_evaluations_created_at", "auto_patch_evaluations", ["created_at"])

def downgrade() -> None:
    op.drop_index("ix_auto_patch_evaluations_created_at", table_name="auto_patch_evaluations")
    op.drop_index("ix_auto_patch_evaluations_create_drafts", table_name="auto_patch_evaluations")
    op.drop_index("ix_auto_patch_evaluations_actor", table_name="auto_patch_evaluations")
    op.drop_table("auto_patch_evaluations")
