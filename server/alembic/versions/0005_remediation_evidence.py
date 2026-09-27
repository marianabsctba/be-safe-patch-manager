"""Add remediation evidence lifecycle.

Revision ID: 0005_remediation_evidence
Revises: 0004_agent_mtls
Create Date: 2026-09-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_remediation_evidence"
down_revision: Union[str, None] = "0004_agent_mtls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediation_evidence",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("campaign_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("cve", sa.String(64), nullable=False),
        sa.Column("greenbone_task_id", sa.String(64), nullable=False),
        sa.Column("baseline_report_id", sa.String(255), nullable=False),
        sa.Column("rescan_report_id", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["vulnerability_findings.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["patch_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_remediation_evidence_job"),
    )
    op.create_index("ix_remediation_evidence_finding_id", "remediation_evidence", ["finding_id"])
    op.create_index("ix_remediation_evidence_campaign_id", "remediation_evidence", ["campaign_id"])
    op.create_index("ix_remediation_evidence_job_id", "remediation_evidence", ["job_id"])
    op.create_index("ix_remediation_evidence_agent_id", "remediation_evidence", ["agent_id"])
    op.create_index("ix_remediation_evidence_cve", "remediation_evidence", ["cve"])
    op.create_index("ix_remediation_evidence_greenbone_task_id", "remediation_evidence", ["greenbone_task_id"])
    op.create_index("ix_remediation_evidence_rescan_report_id", "remediation_evidence", ["rescan_report_id"])
    op.create_index("ix_remediation_evidence_status", "remediation_evidence", ["status"])


def downgrade() -> None:
    op.drop_table("remediation_evidence")
