"""Initial Patch Manager schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_family", sa.String(32), nullable=False),
        sa.Column("os_name", sa.String(255), nullable=False),
        sa.Column("os_version", sa.String(255), nullable=False),
        sa.Column("arch", sa.String(64), nullable=False),
        sa.Column("ip_address", sa.String(128), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reboot_required", sa.Boolean(), nullable=False),
        sa.Column("pending_updates", sa.Integer(), nullable=False),
        sa.Column("critical_updates", sa.Integer(), nullable=False),
        sa.Column("inventory_json", sa.Text(), nullable=False),
        sa.Column("patch_scan_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_agents_hostname", "agents", ["hostname"])

    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("target_os", sa.String(32), nullable=False),
        sa.Column("target_tag", sa.String(128), nullable=False),
        sa.Column("ring_percent", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("allow_reboot", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "integration_states",
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=False),
        sa.Column("object_id", sa.String(64), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "patch_jobs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("campaign_id", sa.String(36), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_patch_jobs_agent_id", "patch_jobs", ["agent_id"])
    op.create_index("ix_patch_jobs_campaign_id", "patch_jobs", ["campaign_id"])

    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(128), nullable=False),
        sa.Column("cve", sa.String(64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=False),
        sa.Column("port", sa.String(128), nullable=False),
        sa.Column("solution", sa.Text(), nullable=False),
        sa.Column("patch_refs_json", sa.Text(), nullable=False),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", "cve", name="uq_vulnerability_source_external_cve"),
    )
    op.create_index("ix_vulnerability_findings_agent_id", "vulnerability_findings", ["agent_id"])
    op.create_index("ix_vulnerability_findings_cve", "vulnerability_findings", ["cve"])
    op.create_index("ix_vulnerability_findings_ip_address", "vulnerability_findings", ["ip_address"])
    op.create_index("ix_vulnerability_findings_severity", "vulnerability_findings", ["severity"])
    op.create_index("ix_vulnerability_findings_source", "vulnerability_findings", ["source"])
    op.create_index("ix_vulnerability_findings_status", "vulnerability_findings", ["status"])


def downgrade() -> None:
    op.drop_table("vulnerability_findings")
    op.drop_table("patch_jobs")
    op.drop_table("audit_events")
    op.drop_table("integration_states")
    op.drop_table("campaigns")
    op.drop_table("agents")
