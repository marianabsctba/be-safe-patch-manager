"""Add exception budgets.

Revision ID: 0036_exception_budgets
Revises: 0035_waiver_governance
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0036_exception_budgets"
down_revision: Union[str, None] = "0035_waiver_governance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "exception_budgets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope_type", sa.String(length=32), nullable=False),
        sa.Column("scope_value", sa.String(length=255), nullable=False),
        sa.Column("max_waivers_month", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("max_hours_month", sa.Integer(), nullable=False, server_default="72"),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("scope_type", "scope_value", name="uq_exception_budget_scope"),
    )
    op.create_index("ix_exception_budgets_name", "exception_budgets", ["name"])
    op.create_index("ix_exception_budgets_enabled", "exception_budgets", ["enabled"])
    op.create_index("ix_exception_budgets_scope_type", "exception_budgets", ["scope_type"])
    op.create_index("ix_exception_budgets_scope_value", "exception_budgets", ["scope_value"])

def downgrade() -> None:
    op.drop_index("ix_exception_budgets_scope_value", table_name="exception_budgets")
    op.drop_index("ix_exception_budgets_scope_type", table_name="exception_budgets")
    op.drop_index("ix_exception_budgets_enabled", table_name="exception_budgets")
    op.drop_index("ix_exception_budgets_name", table_name="exception_budgets")
    op.drop_table("exception_budgets")
