"""Add contextual scope to remediation projects.

Revision ID: 0018_project_scope
Revises: 0017_project_intel
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0018_project_scope"
down_revision: Union[str, None] = "0017_project_intel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "remediation_projects",
        sa.Column("scope_filter_json", sa.Text(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("remediation_projects", "scope_filter_json")
