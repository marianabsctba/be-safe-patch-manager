"""Add exception governance fields.

Revision ID: 0035_waiver_governance
Revises: 0034_policy_waivers
Create Date: 2026-09-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0035_waiver_governance"
down_revision: Union[str, None] = "0034_policy_waivers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column("patch_policy_waivers", sa.Column("owner", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("patch_policy_waivers", sa.Column("requested_by", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("patch_policy_waivers", sa.Column("second_approved_by", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("patch_policy_waivers", sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("patch_policy_waivers", sa.Column("status", sa.String(length=32), nullable=False, server_default="approved"))
    op.create_index("ix_patch_policy_waivers_status", "patch_policy_waivers", ["status"])

def downgrade() -> None:
    op.drop_index("ix_patch_policy_waivers_status", table_name="patch_policy_waivers")
    op.drop_column("patch_policy_waivers", "status")
    op.drop_column("patch_policy_waivers", "required_approvals")
    op.drop_column("patch_policy_waivers", "second_approved_by")
    op.drop_column("patch_policy_waivers", "requested_by")
    op.drop_column("patch_policy_waivers", "owner")
