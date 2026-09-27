"""Bind managed agents to mTLS client certificate fingerprints.

Revision ID: 0004_agent_mtls
Revises: 0003_rbac_sessions
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_agent_mtls"
down_revision: Union[str, None] = "0003_rbac_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("client_cert_fingerprint", sa.String(64), nullable=True))
    op.create_index(
        "ix_agents_client_cert_fingerprint",
        "agents",
        ["client_cert_fingerprint"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_agents_client_cert_fingerprint", table_name="agents")
    op.drop_column("agents", "client_cert_fingerprint")
