import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


TEST_DB = Path(__file__).resolve().parent / "test-update-distribution.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "U" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.agent_updates import canonical_manifest_bytes
from app.models import Agent
from app.security import hash_token


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def publish_release(tmp_path, version="0.14.0"):
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "agent-update-public.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    artifact = tmp_path / f"be-safe-patch-agent-{version}.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("patch_agent.py", b"print('release')\n")
        archive.writestr("requirements.txt", b"requests==2.32.3\n")

    key_id = hashlib.sha256(
        private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    manifest = {
        "schema": 2,
        "product": "be-safe-patch-agent",
        "version": version,
        "protocol": 2,
        "capabilities": ["scan_updates", "signed_update_staging_v1"],
        "generated_at": "2026-09-27T18:30:00+00:00",
        "source_commit": "b" * 40,
        "signing_key_id": key_id,
        "artifact": {
            "filename": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "size_bytes": artifact.stat().st_size,
        },
    }
    (tmp_path / "agent-release.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "agent-release.sig").write_bytes(
        private.sign(canonical_manifest_bytes(manifest))
    )
    return manifest, artifact, public_path


def seed_agent(db, version="0.13.0"):
    token = "update-token-" + ("x" * 32)
    agent = Agent(
        id="update-agent",
        hostname="update-host",
        os_family="linux",
        os_name="Linux",
        token_hash=hash_token(token),
        last_seen=main.now(),
        inventory_json=json.dumps({
            "agent": {
                "version": version,
                "protocol": 2,
                "capabilities": ["scan_updates"],
            }
        }),
        patch_scan_json="[]",
    )
    db.add(agent)
    db.commit()
    return agent, token


def configure_release(monkeypatch, tmp_path, public_path):
    monkeypatch.setattr(main, "AGENT_UPDATE_ENABLED", True)
    monkeypatch.setattr(main, "AGENT_RELEASE_DIR", tmp_path)
    monkeypatch.setattr(main, "AGENT_UPDATE_PUBLIC_KEY_FILE", public_path)


def test_agent_receives_only_verified_newer_release(db, tmp_path, monkeypatch):
    manifest, artifact, public = publish_release(tmp_path, "0.14.0")
    configure_release(monkeypatch, tmp_path, public)
    agent, token = seed_agent(db, "0.13.0")

    result = main.agent_update_latest(
        agent.id,
        x_agent_token=token,
        db=db,
    )

    assert result["available"] is True
    assert result["latest_version"] == "0.14.0"
    assert result["manifest"]["artifact"]["sha256"] == manifest["artifact"]["sha256"]
    assert result["signature"]
    assert result["artifact_url"].endswith("/" + artifact.name)


def test_current_agent_does_not_receive_artifact_metadata(db, tmp_path, monkeypatch):
    _, _, public = publish_release(tmp_path, "0.14.0")
    configure_release(monkeypatch, tmp_path, public)
    agent, token = seed_agent(db, "0.14.0")

    result = main.agent_update_latest(agent.id, x_agent_token=token, db=db)

    assert result["available"] is False
    assert result["status"] == "current"
    assert "manifest" not in result
    assert "signature" not in result
    assert "artifact_url" not in result


def test_artifact_endpoint_serves_only_manifest_artifact(db, tmp_path, monkeypatch):
    _, artifact, public = publish_release(tmp_path)
    configure_release(monkeypatch, tmp_path, public)
    agent, token = seed_agent(db)

    response = main.agent_update_artifact(
        agent.id,
        artifact.name,
        x_agent_token=token,
        db=db,
    )
    assert Path(response.path).resolve() == artifact.resolve()

    with pytest.raises(HTTPException) as exc:
        main.agent_update_artifact(
            agent.id,
            "other.zip",
            x_agent_token=token,
            db=db,
        )
    assert exc.value.status_code == 404


def test_tampered_release_is_not_advertised(db, tmp_path, monkeypatch):
    _, artifact, public = publish_release(tmp_path)
    configure_release(monkeypatch, tmp_path, public)
    artifact.write_bytes(artifact.read_bytes() + b"tamper")
    agent, token = seed_agent(db)

    result = main.agent_update_latest(agent.id, x_agent_token=token, db=db)

    assert result["available"] is False
    assert result["status"] == "unavailable"
    assert "mismatch" in result["error"]


def test_admin_release_status_is_sanitized(tmp_path, monkeypatch):
    manifest, _, public = publish_release(tmp_path)
    configure_release(monkeypatch, tmp_path, public)

    result = main.admin_agent_release(_={"role": "viewer"})

    assert result["ready"] is True
    assert result["version"] == manifest["version"]
    assert result["artifact"]["sha256"] == manifest["artifact"]["sha256"]
    assert "signature" not in result
    assert "path" not in json.dumps(result).lower()
