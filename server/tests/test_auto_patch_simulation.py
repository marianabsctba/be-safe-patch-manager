import os
import sys
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-auto-patch-simulation.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "S" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, AssetRiskProfile, AutoPatchEvaluation, AutoPatchPolicy, PatchApplicability


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def add_agent(db, agent_id, os_family="windows", tags=None, external=False):
    agent = Agent(
        id=agent_id, hostname=agent_id + ".local", os_family=os_family,
        os_name=os_family, token_hash="a"*64, tags=main.dump(tags or []),
    )
    db.add(agent)
    db.add(AssetRiskProfile(
        agent_id=agent_id, external_override=external, owner="ops",
        business_service="core", environment="prod", reason="test", updated_by="test",
    ))
    db.add(PatchApplicability(
        id="pa-" + agent_id, patch_key="kb999", agent_id=agent_id,
        status="missing", evidence="agent_scan",
    ))
    db.commit()


def policy(db):
    p = AutoPatchPolicy(
        id="p1", name="Prod External", enabled=True, mode="recommend",
        target_os="windows", target_tag="prod", require_kev=False,
        require_external=True, require_patch_tuesday=False,
        min_missing_assets=1, confidence_floor="insufficient_data",
        allow_eol=False, superseded_action="replace", ring_percent=20,
        require_approval=True, require_health_gate=True, require_rollback=True,
        created_by="user:admin", updated_by="user:admin",
    )
    db.add(p); db.commit(); return p


def item():
    return {
        "patch_ref":"KB999","patch_key":"kb999","title":"Patch",
        "vendor":"Microsoft","product":"Windows","severity":"critical",
        "states":{"missing":4},"threat":{"kev_findings":0},
        "lifecycle":{"patch_tuesday":False,"eol_state":"supported"},
        "supersedence":{"obsolete":False,"preferred_replacement":None},
        "patch_confidence":{"confidence":"medium"},
    }


def test_scope_funnel_explains_exclusions(monkeypatch, db):
    add_agent(db,"a1","windows",["prod"],True)
    add_agent(db,"a2","linux",["prod"],True)
    add_agent(db,"a3","windows",["dev"],True)
    add_agent(db,"a4","windows",["prod"],False)
    p=policy(db)
    scope=main._auto_patch_scope_analysis(db,p,item())
    assert scope["missing_total"]==4
    assert scope["excluded_os"]==1
    assert scope["excluded_tag"]==1
    assert scope["excluded_external"]==1
    assert scope["selected"]==1
    assert scope["selected_sample"][0]["hostname"]=="a1.local"


def test_report_exposes_blast_radius(monkeypatch, db):
    add_agent(db,"a1","windows",["prod"],True)
    p=policy(db)
    monkeypatch.setattr(main,"patch_catalog_report",lambda db,limit=2000:{"items":[item()]})
    report=main.auto_patch_policy_report(db)
    d=report["decisions"][0]
    assert d["blast_radius"]["selected_assets"]==1
    assert d["blast_radius"]["initial_ring_assets"]==1
    assert d["scope"]["selected"]==1


def test_evaluation_ledger_persists_snapshot(db):
    result={"summary":{"policies":1,"decisions":2,"drafts_created":0,"blocked":1,"holds":0,"ready":1},"decisions":[{"status":"recommend"}]}
    entry=main.persist_auto_patch_evaluation(db,result,"user:operator",False)
    assert db.query(AutoPatchEvaluation).count()==1
    serialized=main.serialize_auto_patch_evaluation(entry,include_result=True)
    assert serialized["actor"]=="user:operator"
    assert serialized["result"]["decisions"][0]["status"]=="recommend"


def test_simulation_returns_scope_and_preconditions(monkeypatch, db):
    add_agent(db,"a1","windows",["prod"],True)
    p=policy(db)
    monkeypatch.setattr(main,"patch_catalog_report",lambda db,limit=2000:{"items":[item()]})
    result=main.auto_patch_simulation(db,p,"KB999")
    assert result["scope"]["selected"]==1
    assert result["preconditions"]["external"]["required"] is True
    assert result["preconditions"]["confidence"]["actual"]=="medium"
