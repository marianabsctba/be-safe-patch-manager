"""Add tenant localization settings.

Revision ID: 0031_tenant_locale
Revises: 0030_campaign_preflight
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0031_tenant_locale"
down_revision: Union[str, None] = "0030_campaign_preflight"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_settings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default="Be Safe"),
        sa.Column("locale", sa.String(length=16), nullable=False, server_default="pt-BR"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tenant_settings_locale", "tenant_settings", ["locale"])


def downgrade() -> None:
    op.drop_index("ix_tenant_settings_locale", table_name="tenant_settings")
    op.drop_table("tenant_settings")
