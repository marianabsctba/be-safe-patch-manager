"""Add patch feed providers.

Revision ID: 0024_patch_feed_providers
Revises: 0023_patch_metadata_evidence
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0024_patch_feed_providers"
down_revision: Union[str, None] = "0023_patch_metadata_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_feed_providers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider_type", sa.String(length=64), nullable=False, server_default="curated"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("ttl_hours", sa.Integer(), nullable=False, server_default="168"),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("failure_threshold", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default="1800"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("circuit_open_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("records_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_patch_feed_providers_name", "patch_feed_providers", ["name"], unique=True)
    op.create_index("ix_patch_feed_providers_provider_type", "patch_feed_providers", ["provider_type"])
    op.create_index("ix_patch_feed_providers_enabled", "patch_feed_providers", ["enabled"])
    op.create_index("ix_patch_feed_providers_circuit_open_until", "patch_feed_providers", ["circuit_open_until"])


def downgrade() -> None:
    op.drop_index("ix_patch_feed_providers_circuit_open_until", table_name="patch_feed_providers")
    op.drop_index("ix_patch_feed_providers_enabled", table_name="patch_feed_providers")
    op.drop_index("ix_patch_feed_providers_provider_type", table_name="patch_feed_providers")
    op.drop_index("ix_patch_feed_providers_name", table_name="patch_feed_providers")
    op.drop_table("patch_feed_providers")
