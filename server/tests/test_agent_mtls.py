import importlib.util
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-mtls.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "M" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent
from app.schemas import RegisterRequest


spec = importlib.util.spec_from_file_location(
    "patch_agent_under_test",
    REPO_ROOT / "agent" / "patch_agent.py",
)
patch_agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_agent)


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


def fingerprint(char="a"):
    return char * 40


def colon_fingerprint(char="a"):
    raw = fingerprint(char).upper()
    return ":".join(raw[i:i + 2] for i in range(0, len(raw), 2))


def registration_body(hostname="lab-linux-01"):
    return RegisterRequest(
        hostname=hostname,
        os_family="linux",
        os_name="Linux",
        os_version="test",
        arch="x86_64",
        ip_address="10.0.0.10",
        tags=["pilot"],
    )


def test_mtls_registration_binds_fingerprint_and_agent_token(db, monkeypatch):
    monkeypatch.setattr(main, "AGENT_MTLS_REQUIRED", True)

    response = main.register_agent(
        registration_body(),
        _=True,
        x_client_cert_fingerprint=colon_fingerprint("a"),
        db=db,
    )

    agent = db.get(Agent, response.agent_id)
    assert agent is not None
    assert agent.client_cert_fingerprint == fingerprint("a")

    authenticated = main.get_agent(
        db,
        response.agent_id,
        response.agent_token,
        fingerprint("a"),
    )
    assert authenticated.id == response.agent_id


def test_mtls_rejects_missing_or_wrong_certificate(db, monkeypatch):
    monkeypatch.setattr(main, "AGENT_MTLS_REQUIRED", True)

    response = main.register_agent(
        registration_body(),
        _=True,
        x_client_cert_fingerprint=fingerprint("b"),
        db=db,
    )

    with pytest.raises(HTTPException) as missing:
        main.get_agent(db, response.agent_id, response.agent_token, None)
    assert missing.value.status_code == 401

    with pytest.raises(HTTPException) as wrong:
        main.get_agent(db, response.agent_id, response.agent_token, fingerprint("c"))
    assert wrong.value.status_code == 401


def test_client_certificate_cannot_be_bound_to_two_agents(db, monkeypatch):
    monkeypatch.setattr(main, "AGENT_MTLS_REQUIRED", True)

    main.register_agent(
        registration_body("host-one"),
        _=True,
        x_client_cert_fingerprint=fingerprint("d"),
        db=db,
    )

    with pytest.raises(HTTPException) as duplicate:
        main.register_agent(
            registration_body("host-two"),
            _=True,
            x_client_cert_fingerprint=fingerprint("d"),
            db=db,
        )
    assert duplicate.value.status_code == 409


def test_agent_tls_options_require_https_and_do_not_allow_verify_false(tmp_path):
    cert = tmp_path / "agent.crt"
    key = tmp_path / "agent.key"
    ca = tmp_path / "ca.crt"
    cert.write_text("certificate", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    ca.write_text("ca", encoding="utf-8")

    options = patch_agent.tls_request_options({
        "tls_verify": True,
        "ca_cert": str(ca),
        "client_cert": str(cert),
        "client_key": str(key),
    })
    assert options["verify"] == str(ca)
    assert options["cert"] == (str(cert), str(key))

    with pytest.raises(RuntimeError, match="tls_verify=false"):
        patch_agent.tls_request_options({"tls_verify": False})

    with pytest.raises(RuntimeError, match="https://"):
        patch_agent.api(
            {
                "server_url": "http://127.0.0.1:8080",
                "tls_verify": True,
            },
            "GET",
            "/health",
        )
