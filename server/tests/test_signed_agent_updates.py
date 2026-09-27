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
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
sys.path.insert(0, str(SERVER_ROOT))

from app.agent_updates import (
    AgentReleaseError,
    canonical_manifest_bytes,
    load_signed_release,
)


spec = importlib.util.spec_from_file_location(
    "patch_agent_update_under_test",
    REPO_ROOT / "agent" / "patch_agent.py",
)
patch_agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_agent)


def keypair(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "signing-private.pem"
    public_path = tmp_path / "signing-public.pem"
    private_path.write_bytes(
        private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private, private_path, public_path


def artifact_zip(path, files=None):
    files = files or {
        "patch_agent.py": b"print('signed agent')\n",
        "requirements.txt": b"requests==2.32.3\n",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def signed_release(tmp_path, *, version="0.14.0", files=None):
    private, _, public = keypair(tmp_path)
    artifact = artifact_zip(
        tmp_path / f"be-safe-patch-agent-{version}.zip",
        files=files,
    )
    manifest = {
        "schema": 1,
        "product": "be-safe-patch-agent",
        "version": version,
        "protocol": 2,
        "capabilities": [
            "scan_updates",
            "install_updates",
            "job_leases_v1",
            "signed_update_staging_v1",
        ],
        "generated_at": "2026-09-27T18:00:00+00:00",
        "artifact": {
            "filename": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "size_bytes": artifact.stat().st_size,
        },
    }
    signature = private.sign(canonical_manifest_bytes(manifest))
    (tmp_path / "agent-release.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "agent-release.sig").write_bytes(signature)
    return manifest, signature, public, artifact


def test_server_release_verifier_accepts_valid_release(tmp_path):
    manifest, _, public, artifact = signed_release(tmp_path)

    release = load_signed_release(tmp_path, public)

    assert release["manifest"]["version"] == "0.14.0"
    assert release["artifact_path"] == artifact.resolve()
    assert release["manifest"]["artifact"]["sha256"] == manifest["artifact"]["sha256"]


def test_server_release_verifier_rejects_manifest_tamper(tmp_path):
    _, _, public, _ = signed_release(tmp_path)
    path = tmp_path / "agent-release.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = "9.9.9"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(AgentReleaseError, match="signature"):
        load_signed_release(tmp_path, public)


def test_server_release_verifier_rejects_artifact_tamper(tmp_path):
    _, _, public, artifact = signed_release(tmp_path)
    artifact.write_bytes(artifact.read_bytes() + b"tamper")

    with pytest.raises(AgentReleaseError, match="size mismatch|SHA-256 mismatch"):
        load_signed_release(tmp_path, public)


def test_agent_stages_verified_update_without_activating_live_agent(tmp_path, monkeypatch):
    manifest, signature, public, artifact = signed_release(tmp_path)
    staging = tmp_path / "staging"
    cfg = {
        "server_url": "https://patch.example.invalid",
        "agent_id": "agent-one",
        "agent_token": "agent-token",
        "update_public_key": str(public),
        "update_staging_dir": str(staging),
    }

    metadata = {
        "enabled": True,
        "available": True,
        "status": "available",
        "latest_version": manifest["version"],
        "manifest": manifest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "artifact_url": f"/api/agent/agent-one/updates/artifact/{artifact.name}",
    }
    monkeypatch.setattr(patch_agent, "api", lambda *args, **kwargs: metadata)

    def fake_download(cfg, artifact_url, destination, expected_size):
        destination.write_bytes(artifact.read_bytes())
        assert destination.stat().st_size == expected_size
        return hashlib.sha256(destination.read_bytes()).hexdigest()

    monkeypatch.setattr(patch_agent, "download_update_artifact", fake_download)

    live_agent_before = (REPO_ROOT / "agent" / "patch_agent.py").read_bytes()
    state = patch_agent.stage_signed_update(cfg)
    live_agent_after = (REPO_ROOT / "agent" / "patch_agent.py").read_bytes()

    assert state["status"] == "staged"
    assert state["staged_version"] == "0.14.0"
    assert state["activation"] == "manual"
    assert (staging / "0.14.0" / "payload" / "patch_agent.py").is_file()
    assert (staging / "0.14.0" / "payload" / "requirements.txt").is_file()
    assert live_agent_after == live_agent_before


def test_agent_rejects_signed_downgrade(tmp_path, monkeypatch):
    manifest, signature, public, artifact = signed_release(tmp_path, version="0.13.9")
    cfg = {
        "server_url": "https://patch.example.invalid",
        "agent_id": "agent-one",
        "agent_token": "agent-token",
        "update_public_key": str(public),
        "update_staging_dir": str(tmp_path / "staging"),
    }
    monkeypatch.setattr(
        patch_agent,
        "api",
        lambda *args, **kwargs: {
            "enabled": True,
            "available": True,
            "manifest": manifest,
            "signature": base64.b64encode(signature).decode("ascii"),
            "artifact_url": f"/api/agent/agent-one/updates/artifact/{artifact.name}",
        },
    )

    with pytest.raises(RuntimeError, match="non-upgrade"):
        patch_agent.stage_signed_update(cfg)


def test_agent_rejects_archive_with_unexpected_path(tmp_path, monkeypatch):
    manifest, signature, public, artifact = signed_release(
        tmp_path,
        files={
            "patch_agent.py": b"safe",
            "requirements.txt": b"safe",
            "../escape.py": b"bad",
        },
    )
    cfg = {
        "server_url": "https://patch.example.invalid",
        "agent_id": "agent-one",
        "agent_token": "agent-token",
        "update_public_key": str(public),
        "update_staging_dir": str(tmp_path / "staging"),
    }
    monkeypatch.setattr(
        patch_agent,
        "api",
        lambda *args, **kwargs: {
            "enabled": True,
            "available": True,
            "manifest": manifest,
            "signature": base64.b64encode(signature).decode("ascii"),
            "artifact_url": f"/api/agent/agent-one/updates/artifact/{artifact.name}",
        },
    )

    def fake_download(cfg, artifact_url, destination, expected_size):
        destination.write_bytes(artifact.read_bytes())
        return hashlib.sha256(destination.read_bytes()).hexdigest()

    monkeypatch.setattr(patch_agent, "download_update_artifact", fake_download)

    with pytest.raises(RuntimeError, match="unexpected files|unsafe paths"):
        patch_agent.stage_signed_update(cfg)


def test_agent_rejects_tampered_signature_before_download(tmp_path, monkeypatch):
    manifest, signature, public, artifact = signed_release(tmp_path)
    bad_signature = bytearray(signature)
    bad_signature[0] ^= 0x01
    cfg = {
        "server_url": "https://patch.example.invalid",
        "agent_id": "agent-one",
        "agent_token": "agent-token",
        "update_public_key": str(public),
        "update_staging_dir": str(tmp_path / "staging"),
    }
    monkeypatch.setattr(
        patch_agent,
        "api",
        lambda *args, **kwargs: {
            "enabled": True,
            "available": True,
            "manifest": manifest,
            "signature": base64.b64encode(bytes(bad_signature)).decode("ascii"),
            "artifact_url": f"/api/agent/agent-one/updates/artifact/{artifact.name}",
        },
    )
    called = {"download": False}

    def never_download(*args, **kwargs):
        called["download"] = True
        raise AssertionError("artifact must not be downloaded")

    monkeypatch.setattr(patch_agent, "download_update_artifact", never_download)

    with pytest.raises(RuntimeError, match="signature verification failed"):
        patch_agent.stage_signed_update(cfg)
    assert called["download"] is False
