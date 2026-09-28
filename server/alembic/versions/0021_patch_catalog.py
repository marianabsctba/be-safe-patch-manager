"""Add patch catalog and applicability observations.

Revision ID: 0021_patch_catalog
Revises: 0020_campaign_approvals
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0021_patch_catalog"
down_revision: Union[str, None] = "0020_campaign_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_catalog_entries",
        sa.Column("patch_key", sa.String(length=255), nullable=False),
        sa.Column("patch_ref", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("product", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("title", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("version", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("reboot_behavior", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="agent_scan"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("patch_key"),
    )
    op.create_index("ix_patch_catalog_entries_patch_ref", "patch_catalog_entries", ["patch_ref"])
    op.create_index("ix_patch_catalog_entries_severity", "patch_catalog_entries", ["severity"])
    op.create_index("ix_patch_catalog_entries_last_seen", "patch_catalog_entries", ["last_seen"])

    op.create_table(
        "patch_applicability",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("patch_key", sa.String(length=255), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="missing"),
        sa.Column("evidence", sa.String(length=64), nullable=False, server_default="agent_scan"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.ForeignKeyConstraint(["patch_key"], ["patch_catalog_entries.patch_key"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("patch_key", "agent_id", name="uq_patch_applicability_patch_agent"),
    )
    op.create_index("ix_patch_applicability_patch_key", "patch_applicability", ["patch_key"])
    op.create_index("ix_patch_applicability_agent_id", "patch_applicability", ["agent_id"])
    op.create_index("ix_patch_applicability_status", "patch_applicability", ["status"])
    op.create_index("ix_patch_applicability_last_seen", "patch_applicability", ["last_seen"])


def downgrade() -> None:
    op.drop_index("ix_patch_applicability_last_seen", table_name="patch_applicability")
    op.drop_index("ix_patch_applicability_status", table_name="patch_applicability")
    op.drop_index("ix_patch_applicability_agent_id", table_name="patch_applicability")
    op.drop_index("ix_patch_applicability_patch_key", table_name="patch_applicability")
    op.drop_table("patch_applicability")
    op.drop_index("ix_patch_catalog_entries_last_seen", table_name="patch_catalog_entries")
    op.drop_index("ix_patch_catalog_entries_severity", table_name="patch_catalog_entries")
    op.drop_index("ix_patch_catalog_entries_patch_ref", table_name="patch_catalog_entries")
    op.drop_table("patch_catalog_entries")
