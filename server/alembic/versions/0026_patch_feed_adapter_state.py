"""Add patch feed adapter configuration and state.

Revision ID: 0026_patch_feed_adapter_state
Revises: 0025_change_freeze
Create Date: 2026-09-28
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "0026_patch_feed_adapter_state"
down_revision: Union[str, None] = "0025_change_freeze"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
def upgrade() -> None:
    op.add_column("patch_feed_providers", sa.Column("provider_config_json", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("patch_feed_providers", sa.Column("adapter_state_json", sa.Text(), nullable=False, server_default="{}"))
def downgrade() -> None:
    op.drop_column("patch_feed_providers", "adapter_state_json")
    op.drop_column("patch_feed_providers", "provider_config_json")
