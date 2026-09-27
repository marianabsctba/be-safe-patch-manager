import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "patch_agent_health_under_test",
    REPO_ROOT / "agent" / "patch_agent.py",
)
patch_agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_agent)


def test_remote_application_health_url_is_rejected_without_network_call(monkeypatch):
    def fail_request(*args, **kwargs):
        raise AssertionError("remote health URL must never be requested")

    monkeypatch.setattr(patch_agent.requests, "get", fail_request)

    result = patch_agent.collect_application_health([
        {"name": "remote", "url": "https://example.com/health"}
    ])

    assert result["remote"]["healthy"] is False
    assert "loopback" in result["remote"]["error"]


def test_collect_health_returns_bounded_system_snapshot(monkeypatch):
    monkeypatch.setattr(patch_agent.psutil, "cpu_percent", lambda interval=0: 12.0)
    monkeypatch.setattr(
        patch_agent.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(percent=44.5),
    )
    monkeypatch.setattr(
        patch_agent.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1000, free=420),
    )
    monkeypatch.setattr(
        patch_agent,
        "collect_service_health",
        lambda names: {"nginx": {"healthy": True, "status": "active"}},
    )
    monkeypatch.setattr(
        patch_agent,
        "collect_application_health",
        lambda checks: {"api": {"healthy": True, "status_code": 200, "latency_ms": 5.0}},
    )

    result = patch_agent.collect_health({
        "enabled": True,
        "critical_services": ["nginx"],
        "application_checks": [{"name": "api", "url": "http://127.0.0.1/health"}],
    })

    assert result["cpu_percent"] == 12.0
    assert result["memory_percent"] == 44.5
    assert result["disk"]["free_percent"] == 42.0
    assert result["services"]["nginx"]["healthy"] is True
    assert result["applications"]["api"]["healthy"] is True
    assert result["policy_enabled"] is True


def test_execute_install_persists_policy_and_reports_health_baseline(tmp_path, monkeypatch):
    cfg_path = tmp_path / "agent.json"
    cfg = {
        "agent_id": "agent-one",
        "agent_token": "agent-token",
        "server_url": "https://127.0.0.1",
    }
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    snapshots = [
        {"collected_at": "2026-09-27T12:00:00+00:00", "cpu_percent": 10},
        {"collected_at": "2026-09-27T12:01:00+00:00", "cpu_percent": 12},
    ]
    monkeypatch.setattr(patch_agent, "collect_health", lambda policy=None: snapshots.pop(0))
    monkeypatch.setattr(
        patch_agent,
        "install_updates",
        lambda payload: {"installed": ["openssl"], "reboot_required": False},
    )
    monkeypatch.setattr(patch_agent, "scan_updates", lambda: [])
    monkeypatch.setattr(
        patch_agent,
        "create_rollback_checkpoint",
        lambda job_id: {"status": "disabled"},
    )

    sent = []

    def fake_send(cfg, job_id, status, claim_token, result=None, error="", started_at=None, finished_at=None):
        sent.append({
            "status": status,
            "result": result or {},
            "error": error,
        })
        return {"ok": True}

    monkeypatch.setattr(patch_agent, "send_job_result", fake_send)

    job = {
        "id": "job-health",
        "claim_token": "claim-token-1234567890",
        "lease_seconds": 300,
        "action": "install_updates",
        "payload": {
            "packages": ["openssl"],
            "prepare_rollback": False,
            "health_policy": {
                "enabled": True,
                "required": True,
                "policy_ttl_seconds": 86400,
                "critical_services": [],
                "application_checks": [],
            },
        },
    }

    patch_agent.execute_job(cfg, job, cfg_path)

    assert sent[0]["status"] == "running"
    assert sent[-1]["status"] == "success"
    assert sent[-1]["result"]["health_baseline"]["cpu_percent"] == 10
    assert sent[-1]["result"]["health_post"]["cpu_percent"] == 12

    stored = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert stored["_active_health_policy"]["enabled"] is True
    assert stored["_active_health_policy_expires_at"] > 0


def test_invalid_service_name_fails_closed():
    result = patch_agent.collect_service_health(["nginx;rm -rf /"])

    item = result["nginx;rm -rf /"]
    assert item["healthy"] is False
    assert item["status"] == "invalid_name"



def test_inventory_reports_agent_runtime_metadata(monkeypatch):
    monkeypatch.setattr(
        patch_agent,
        "rollback_capability",
        lambda: {"checkpoint_supported": False, "automatic_restore": False},
    )

    data = patch_agent.inventory()

    assert data["agent"]["version"] == "0.14.0"
    assert data["agent"]["protocol"] == 2
    assert "install_updates" in data["agent"]["capabilities"]
    assert "health_telemetry_v1" in data["agent"]["capabilities"]
    assert "job_leases_v1" in data["agent"]["capabilities"]


def test_user_agent_uses_runtime_version(monkeypatch):
    captured = {}

    class FakeResponse:
        content = b"{}"

        def raise_for_status(self):
            return None

        def json(self):
            return {}

    def fake_request(method, url, **kwargs):
        captured["headers"] = kwargs.get("headers") or {}
        return FakeResponse()

    monkeypatch.setattr(patch_agent, "tls_request_options", lambda cfg: {"verify": True, "cert": None})
    monkeypatch.setattr(patch_agent.requests, "request", fake_request)

    patch_agent.api(
        {"server_url": "https://127.0.0.1"},
        "GET",
        "/health",
    )

    assert captured["headers"]["User-Agent"] == "PatchManagerAgent/0.14.0"
