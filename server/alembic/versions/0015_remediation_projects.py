"""Add remediation projects.

Revision ID: 0015_remediation_projects
Revises: 0014_risk_reduction_goals
Create Date: 2026-09-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0015_remediation_projects"
down_revision: Union[str, None] = "0014_risk_reduction_goals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediation_projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("patch_ref", sa.String(255), nullable=False),
        sa.Column("scope_mode", sa.String(32), nullable=False, server_default="static"),
        sa.Column("scope_tag", sa.String(128), nullable=False, server_default=""),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("baseline_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("baseline_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("baseline_risk_reduction", sa.Float(), nullable=False, server_default="0"),
        sa.Column("scope_snapshot_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_projects_name", "remediation_projects", ["name"], unique=True)
    op.create_index("ix_remediation_projects_patch_ref", "remediation_projects", ["patch_ref"])
    op.create_index("ix_remediation_projects_scope_tag", "remediation_projects", ["scope_tag"])
    op.create_index("ix_remediation_projects_due_at", "remediation_projects", ["due_at"])
    op.create_index("ix_remediation_projects_status", "remediation_projects", ["status"])


def downgrade() -> None:
    op.drop_index("ix_remediation_projects_status", table_name="remediation_projects")
    op.drop_index("ix_remediation_projects_due_at", table_name="remediation_projects")
    op.drop_index("ix_remediation_projects_scope_tag", table_name="remediation_projects")
    op.drop_index("ix_remediation_projects_patch_ref", table_name="remediation_projects")
    op.drop_index("ix_remediation_projects_name", table_name="remediation_projects")
    op.drop_table("remediation_projects")
