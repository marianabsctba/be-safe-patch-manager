import base64
import hashlib
import importlib.util
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


REPO_ROOT = Path(__file__).resolve().parents[2]

agent_spec = importlib.util.spec_from_file_location(
    "patch_agent_activation_under_test",
    REPO_ROOT / "agent" / "patch_agent.py",
)
patch_agent = importlib.util.module_from_spec(agent_spec)
agent_spec.loader.exec_module(patch_agent)

launcher_spec = importlib.util.spec_from_file_location(
    "agent_launcher_under_test",
    REPO_ROOT / "agent" / "agent_launcher.py",
)
launcher = importlib.util.module_from_spec(launcher_spec)
launcher_spec.loader.exec_module(launcher)


def create_signed_stage(tmp_path, *, version="0.16.0", requirements=None):
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "agent-update-public.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    )

    staging_root = tmp_path / "updates"
    stage = staging_root / version
    stage.mkdir(parents=True)

    requirements = requirements or (REPO_ROOT / "agent" / "requirements.txt").read_bytes()
    future_agent = (
        '#!/usr/bin/env python3\n'
        'import argparse\n'
        f'AGENT_VERSION = "{version}"\n'
        'p=argparse.ArgumentParser()\n'
        'p.add_argument("--config")\n'
        'p.parse_args()\n'
    ).encode("utf-8")

    artifact = stage / f"be-safe-patch-agent-{version}.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("patch_agent.py", future_agent)
        archive.writestr("requirements.txt", requirements)

    manifest = {
        "schema": 1,
        "product": "be-safe-patch-agent",
        "version": version,
        "protocol": 2,
        "capabilities": [
            "scan_updates",
            "job_leases_v1",
            "signed_update_staging_v1",
            "signed_update_activation_v1",
        ],
        "generated_at": "2026-09-27T19:00:00+00:00",
        "artifact": {
            "filename": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "size_bytes": artifact.stat().st_size,
        },
    }
    signature = private.sign(patch_agent.canonical_update_manifest(manifest))
    (stage / "agent-release.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (stage / "agent-release.sig").write_bytes(signature)

    return staging_root, public_path, manifest, artifact


def managed_layout(tmp_path):
    base = tmp_path / "agent-base"
    releases = base / "releases"
    current_release = releases / "0.15.0"
    current_release.mkdir(parents=True)
    current_release.joinpath("patch_agent.py").write_text(
        'AGENT_VERSION = "0.15.0"\n',
        encoding="utf-8",
    )
    current_release.joinpath("requirements.txt").write_bytes(
        (REPO_ROOT / "agent" / "requirements.txt").read_bytes()
    )
    os.symlink("releases/0.15.0", base / "current")
    return base, current_release


def config(tmp_path, base, staging_root, public_path):
    return {
        "agent_id": "agent-one",
        "agent_token": "token",
        "server_url": "https://patch.example.invalid",
        "update_public_key": str(public_path),
        "update_staging_dir": str(staging_root),
        "agent_base_dir": str(base),
        "activation_state_file": str(tmp_path / "activation.json"),
    }


def mark_staged(cfg, version="0.16.0"):
    patch_agent.write_update_state(cfg, {
        "status": "staged",
        "staged_version": version,
        "activation": "manual",
    })


def test_linux_activation_swaps_current_atomically_and_marks_pending(tmp_path):
    base, previous = managed_layout(tmp_path)
    staging, public, _, _ = create_signed_stage(tmp_path)
    cfg = config(tmp_path, base, staging, public)
    mark_staged(cfg)

    result = patch_agent.activate_staged_update(cfg, "0.16.0", "job-one")

    assert result["status"] == "activation_prepared"
    assert result["previous_version"] == "0.15.0"
    assert result["target_version"] == "0.16.0"
    assert (base / "current").resolve() == (base / "releases" / "0.16.0").resolve()
    assert previous.is_dir()

    state = patch_agent.read_activation_state(cfg)
    assert state["status"] == "pending"
    assert state["attempts"] == 0
    assert state["job_id"] == "job-one"

    update = patch_agent.read_update_state(cfg)
    assert update["status"] == "activating"
    assert update["target_version"] == "0.16.0"


def test_successful_heartbeat_confirmation_commits_activation(tmp_path, monkeypatch):
    base, _ = managed_layout(tmp_path)
    staging, public, _, _ = create_signed_stage(tmp_path)
    cfg = config(tmp_path, base, staging, public)
    mark_staged(cfg)
    patch_agent.activate_staged_update(cfg, "0.16.0", "job-one")

    monkeypatch.setattr(patch_agent, "AGENT_VERSION", "0.16.0")
    assert patch_agent.confirm_pending_activation(cfg) is True

    state = patch_agent.read_activation_state(cfg)
    assert state["status"] == "committed"
    assert state["confirmed_version"] == "0.16.0"

    update = patch_agent.read_update_state(cfg)
    assert update["status"] == "activated"
    assert update["active_version"] == "0.16.0"


def test_launcher_rolls_back_after_repeated_unconfirmed_boots(tmp_path):
    base, previous = managed_layout(tmp_path)
    target = base / "releases" / "0.16.0"
    target.mkdir()
    target.joinpath("patch_agent.py").write_text("raise SystemExit(1)\n", encoding="utf-8")
    target.joinpath("requirements.txt").write_text("same\n", encoding="utf-8")
    (base / "current").unlink()
    os.symlink("releases/0.16.0", base / "current")

    state_path = tmp_path / "activation.json"
    launcher.write_state(state_path, {
        "status": "pending",
        "previous_version": "0.15.0",
        "target_version": "0.16.0",
        "attempts": 0,
    })

    launcher.reconcile_activation(base, state_path, 2)
    launcher.reconcile_activation(base, state_path, 2)
    state = launcher.reconcile_activation(base, state_path, 2)

    assert state["status"] == "rolled_back"
    assert state["rollback_reason"] == "startup_attempt_limit"
    assert (base / "current").resolve() == previous.resolve()


def test_launcher_marks_switch_aborted_if_symlink_never_changed(tmp_path):
    base, _ = managed_layout(tmp_path)
    target = base / "releases" / "0.16.0"
    target.mkdir()
    target.joinpath("patch_agent.py").write_text("print('ok')\n", encoding="utf-8")

    state_path = tmp_path / "activation.json"
    launcher.write_state(state_path, {
        "status": "switching",
        "previous_version": "0.15.0",
        "target_version": "0.16.0",
        "attempts": 0,
    })

    state = launcher.reconcile_activation(base, state_path, 3)

    assert state["status"] == "aborted_before_switch"
    assert (base / "current").resolve().name == "0.15.0"


def test_activation_rejects_dependency_change(tmp_path):
    base, _ = managed_layout(tmp_path)
    staging, public, _, _ = create_signed_stage(
        tmp_path,
        requirements=b"totally-new-dependency==1.0\n",
    )
    cfg = config(tmp_path, base, staging, public)
    mark_staged(cfg)

    with pytest.raises(RuntimeError, match="dependency changes"):
        patch_agent.activate_staged_update(cfg, "0.16.0", "job-one")

    assert (base / "current").resolve().name == "0.15.0"
    assert not (base / "releases" / "0.16.0").exists()


def test_activation_rejects_legacy_non_symlink_layout(tmp_path):
    base = tmp_path / "legacy"
    base.mkdir()
    (base / "patch_agent.py").write_text("print('legacy')\n", encoding="utf-8")
    staging, public, _, _ = create_signed_stage(tmp_path)
    cfg = config(tmp_path, base, staging, public)
    mark_staged(cfg)

    with pytest.raises(RuntimeError, match="v0.15 installer"):
        patch_agent.activate_staged_update(cfg, "0.16.0", "job-one")
