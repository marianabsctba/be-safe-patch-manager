import os
import sys
from datetime import timedelta
from pathlib import Path
import pytest

TEST_DB=Path(__file__).resolve().parent/"test-change-freeze.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SERVER_ROOT))
os.environ["DATABASE_URL"]=f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"]="Z"*48
os.environ["BREAK_GLASS_ADMIN_TOKEN"]=""
os.environ["GREENBONE_ENABLED"]="false"
os.environ["THREAT_INTEL_ENABLED"]="false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Campaign, PatchFreezeWindow, CampaignFreezeOverride

@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine);Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture()
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()

def campaign():
    return Campaign(id="c1",name="prod patch",target_os="windows",target_tag="prod",ring_percent=10,action="install_updates",status="draft",payload_json="{}")

def window(**kwargs):
    instant=main.now()
    values=dict(id="w1",name="Quarter close",target_os="windows",target_tag="prod",starts_at=instant-timedelta(hours=1),ends_at=instant+timedelta(hours=1),enabled=True,reason="Financial close",created_by="user:admin",updated_by="user:admin")
    values.update(kwargs)
    return PatchFreezeWindow(**values)

def test_matching_freeze_blocks_campaign(db):
    c=campaign();w=window()
    db.add_all([c,w]);db.commit()
    guard=main.campaign_freeze_guard(db,c)
    assert guard["blocked"] is True
    assert guard["windows"][0]["name"]=="Quarter close"

def test_scope_mismatch_does_not_block(db):
    c=campaign();w=window(target_tag="dev")
    db.add_all([c,w]);db.commit()
    assert main.campaign_freeze_guard(db,c)["blocked"] is False

def test_override_unblocks_and_revoke_blocks_again(db):
    c=campaign();w=window()
    db.add_all([c,w]);db.commit()
    o=CampaignFreezeOverride(id="o1",campaign_id=c.id,reason="Emergency KEV remediation",approved_by="user:admin",approved_at=main.now())
    db.add(o);db.commit()
    assert main.campaign_freeze_guard(db,c)["blocked"] is False
    o.revoked_by="user:admin";o.revoked_at=main.now();o.revoke_reason="Emergency ended";db.commit()
    assert main.campaign_freeze_guard(db,c)["blocked"] is True
