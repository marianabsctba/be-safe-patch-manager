from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    hostname: str
    os_family: str
    os_name: str
    os_version: str = ""
    arch: str = ""
    ip_address: str = ""
    tags: List[str] = Field(default_factory=list)


class RegisterResponse(BaseModel):
    agent_id: str
    agent_token: str


class HeartbeatRequest(BaseModel):
    inventory: Dict[str, Any] = Field(default_factory=dict)
    patch_scan: List[Dict[str, Any]] = Field(default_factory=list)
    reboot_required: bool = False


class JobResultRequest(BaseModel):
    status: str
    claim_token: str = ""
    result: Dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class LeaseRenewRequest(BaseModel):
    claim_token: str = Field(min_length=16, max_length=256)


class JobRetryRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    target_os: str = "all"
    target_tag: str = ""
    ring_percent: int = Field(default=10, ge=1, le=100)
    action: str = "install_updates"
    payload: Dict[str, Any] = Field(default_factory=dict)
    not_before: Optional[datetime] = None
    allow_reboot: bool = False
    reboot_policy: str = "never"
    maintenance_start: str = ""
    maintenance_end: str = ""
    maintenance_timezone: str = "America/Sao_Paulo"
    maintenance_days: List[int] = Field(default_factory=lambda: list(range(7)))
    post_patch_validation: bool = True
    prepare_rollback: bool = True
    rollback_required: bool = False
    target_agent_id: str = ""
    target_finding_id: str = ""


class VulnerabilityFindingInput(BaseModel):
    external_id: str = Field(min_length=1, max_length=255)
    host: str = ""
    ip_address: str = ""
    cves: List[str] = Field(default_factory=list)
    title: str = ""
    severity: str = ""
    cvss: float = Field(default=0.0, ge=0.0, le=10.0)
    port: str = ""
    solution: str = ""
    patch_refs: List[str] = Field(default_factory=list)
    resolved: bool = False
    raw: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityImportRequest(BaseModel):
    source: str = Field(default="openvas", min_length=1, max_length=64)
    scan_id: str = ""
    findings: List[VulnerabilityFindingInput] = Field(default_factory=list)


class VulnerabilityStatusUpdate(BaseModel):
    status: str


class RingAdvance(BaseModel):
    target_percent: int = Field(ge=1, le=100)
    override_health_gate: bool = False


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class TagUpdate(BaseModel):
    tags: List[str]
