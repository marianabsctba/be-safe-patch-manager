"""Add patch lifecycle and supersedence metadata.

Revision ID: 0022_patch_lifecycle
Revises: 0021_patch_catalog
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0022_patch_lifecycle"
down_revision: Union[str, None] = "0021_patch_catalog"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("patch_catalog_entries", sa.Column("classification", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("patch_catalog_entries", sa.Column("release_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("patch_catalog_entries", sa.Column("eol_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("patch_catalog_entries", sa.Column("supersedes_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("patch_catalog_entries", sa.Column("lifecycle_source", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("patch_catalog_entries", sa.Column("lifecycle_updated_by", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("patch_catalog_entries", sa.Column("lifecycle_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_patch_catalog_entries_classification", "patch_catalog_entries", ["classification"])
    op.create_index("ix_patch_catalog_entries_release_date", "patch_catalog_entries", ["release_date"])
    op.create_index("ix_patch_catalog_entries_eol_date", "patch_catalog_entries", ["eol_date"])


def downgrade() -> None:
    op.drop_index("ix_patch_catalog_entries_eol_date", table_name="patch_catalog_entries")
    op.drop_index("ix_patch_catalog_entries_release_date", table_name="patch_catalog_entries")
    op.drop_index("ix_patch_catalog_entries_classification", table_name="patch_catalog_entries")
    op.drop_column("patch_catalog_entries", "lifecycle_updated_at")
    op.drop_column("patch_catalog_entries", "lifecycle_updated_by")
    op.drop_column("patch_catalog_entries", "lifecycle_source")
    op.drop_column("patch_catalog_entries", "supersedes_json")
    op.drop_column("patch_catalog_entries", "eol_date")
    op.drop_column("patch_catalog_entries", "release_date")
    op.drop_column("patch_catalog_entries", "classification")
