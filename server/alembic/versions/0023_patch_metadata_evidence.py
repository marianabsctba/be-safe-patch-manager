"""Add patch metadata enrichment evidence.

Revision ID: 0023_patch_metadata_evidence
Revises: 0022_patch_lifecycle
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0023_patch_metadata_evidence"
down_revision: Union[str, None] = "0022_patch_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("patch_catalog_entries", sa.Column("enrichment_json", sa.Text(), nullable=False, server_default="{}"))
    op.create_table(
        "patch_metadata_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("patch_key", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("imported_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["patch_key"], ["patch_catalog_entries.patch_key"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("patch_key", "source", name="uq_patch_metadata_evidence_patch_source"),
    )
    op.create_index("ix_patch_metadata_evidence_patch_key", "patch_metadata_evidence", ["patch_key"])
    op.create_index("ix_patch_metadata_evidence_source", "patch_metadata_evidence", ["source"])
    op.create_index("ix_patch_metadata_evidence_priority", "patch_metadata_evidence", ["priority"])
    op.create_index("ix_patch_metadata_evidence_observed_at", "patch_metadata_evidence", ["observed_at"])
    op.create_index("ix_patch_metadata_evidence_expires_at", "patch_metadata_evidence", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_patch_metadata_evidence_expires_at", table_name="patch_metadata_evidence")
    op.drop_index("ix_patch_metadata_evidence_observed_at", table_name="patch_metadata_evidence")
    op.drop_index("ix_patch_metadata_evidence_priority", table_name="patch_metadata_evidence")
    op.drop_index("ix_patch_metadata_evidence_source", table_name="patch_metadata_evidence")
    op.drop_index("ix_patch_metadata_evidence_patch_key", table_name="patch_metadata_evidence")
    op.drop_table("patch_metadata_evidence")
    op.drop_column("patch_catalog_entries", "enrichment_json")
