import os
import sys
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["ENROLLMENT_TOKEN"] = "D" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app import main


def test_kev_ransomware_external_becomes_p0():
    result = main.remediation_group_decision(
        kev_findings=2,
        ransomware_findings=1,
        high_epss_findings=2,
        max_epss=0.94,
        sla_breached=0,
        sla_due_soon=0,
        external_assets=3,
        critical_assets=1,
        asset_count=25,
        patch_confidence={"confidence": "medium"},
    )

    assert result["priority"]["tier"] == "P0"
    assert result["priority"]["label"] == "remediar agora"
    assert result["deployment_guidance"]["health_gate_required"] is True


def test_low_confidence_critical_scope_uses_guarded_canary():
    result = main.remediation_group_decision(
        kev_findings=0,
        ransomware_findings=0,
        high_epss_findings=0,
        max_epss=0.1,
        sla_breached=0,
        sla_due_soon=0,
        external_assets=0,
        critical_assets=4,
        asset_count=40,
        patch_confidence={"confidence": "low"},
    )

    assert result["change_risk"]["level"] == "high"
    assert result["deployment_guidance"]["mode"] == "guarded_canary"
    assert result["deployment_guidance"]["ring_plan"] == [5, 10, 30, 100]
    assert result["deployment_guidance"]["rollback_checkpoint_required"] is True


def test_high_confidence_small_low_risk_scope_can_start_at_full_ring():
    result = main.remediation_group_decision(
        kev_findings=0,
        ransomware_findings=0,
        high_epss_findings=0,
        max_epss=0.05,
        sla_breached=0,
        sla_due_soon=0,
        external_assets=0,
        critical_assets=0,
        asset_count=4,
        patch_confidence={"confidence": "high"},
    )

    assert result["priority"]["tier"] == "P3"
    assert result["change_risk"]["level"] == "low"
    assert result["deployment_guidance"]["ring_plan"] == [100]
    assert result["deployment_guidance"]["suggested_ring_percent"] == 100


def test_sla_breach_without_threat_signal_is_p1():
    result = main.remediation_group_decision(
        kev_findings=0,
        ransomware_findings=0,
        high_epss_findings=0,
        max_epss=0.1,
        sla_breached=2,
        sla_due_soon=0,
        external_assets=0,
        critical_assets=0,
        asset_count=8,
        patch_confidence={"confidence": "high"},
    )

    assert result["priority"]["tier"] == "P1"
    assert any("SLA vencido" in reason for reason in result["priority"]["reasons"])
