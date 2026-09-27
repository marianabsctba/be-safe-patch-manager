import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_DB = Path(__file__).resolve().parent / "test-auth.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "E" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AdminSession, AdminUser
from app.security import hash_token, password_hash


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


def add_user(db, username, role, password="V3ry-Str0ng-T3st-Key-2026!X"):
    user = AdminUser(
        id=f"user-{username}",
        username=username,
        password_hash=password_hash(password),
        role=role,
        active=True,
    )
    db.add(user)
    db.commit()
    return user, password


def login(client, username, password):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["session_token"]


def test_login_uses_opaque_hashed_server_session(db):
    user, password = add_user(db, "viewer.one", "viewer")
    client = TestClient(app)
    token = login(client, user.username, password)

    session = db.query(AdminSession).filter(AdminSession.user_id == user.id).one()
    assert session.token_hash == hash_token(token)
    assert session.token_hash != token

    response = client.get("/api/auth/me", headers={"X-Session-Token": token})
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"


def test_viewer_can_read_but_cannot_operate_or_manage_users(db):
    user, password = add_user(db, "viewer.two", "viewer")
    client = TestClient(app)
    token = login(client, user.username, password)
    headers = {"X-Session-Token": token}

    assert client.get("/api/admin/summary", headers=headers).status_code == 200
    assert client.put(
        "/api/admin/agents/not-found/tags",
        headers=headers,
        json={"tags": ["pilot"]},
    ).status_code == 403
    assert client.get("/api/admin/users", headers=headers).status_code == 403


def test_operator_can_pass_operation_guard_but_not_admin_guard(db):
    user, password = add_user(db, "operator.one", "operator")
    client = TestClient(app)
    token = login(client, user.username, password)
    headers = {"X-Session-Token": token}

    # 404 proves the operator passed authorization and reached resource lookup.
    assert client.put(
        "/api/admin/agents/not-found/tags",
        headers=headers,
        json={"tags": ["pilot"]},
    ).status_code == 404
    assert client.get("/api/admin/users", headers=headers).status_code == 403


def test_admin_can_manage_users(db):
    admin, password = add_user(db, "admin.one", "admin")
    client = TestClient(app)
    token = login(client, admin.username, password)
    headers = {"X-Session-Token": token}

    response = client.post(
        "/api/admin/users",
        headers=headers,
        json={
            "username": "new.operator",
            "password": "An0ther-Str0ng-Key-2026!Z",
            "role": "operator",
        },
    )
    assert response.status_code == 200
    assert response.json()["role"] == "operator"

    users = client.get("/api/admin/users", headers=headers)
    assert users.status_code == 200
    assert {item["username"] for item in users.json()} == {"admin.one", "new.operator"}


def test_logout_revokes_session(db):
    user, password = add_user(db, "viewer.logout", "viewer")
    client = TestClient(app)
    token = login(client, user.username, password)
    headers = {"X-Session-Token": token}

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_admin_cannot_demote_self_or_remove_last_active_admin(db):
    admin, password = add_user(db, "admin.sole", "admin")
    client = TestClient(app)
    token = login(client, admin.username, password)
    headers = {"X-Session-Token": token}

    self_demote = client.patch(
        f"/api/admin/users/{admin.id}",
        headers=headers,
        json={"role": "viewer"},
    )
    assert self_demote.status_code == 409

    # Create a second admin, then it may be demoted because one admin remains.
    second = client.post(
        "/api/admin/users",
        headers=headers,
        json={
            "username": "admin.second",
            "password": "Sec0nd-Adm1n-Key-2026!Q",
            "role": "admin",
        },
    )
    assert second.status_code == 200

    second_id = second.json()["id"]
    demote_second = client.patch(
        f"/api/admin/users/{second_id}",
        headers=headers,
        json={"role": "operator"},
    )
    assert demote_second.status_code == 200
