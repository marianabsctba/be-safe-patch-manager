from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=14, max_length=512)
    role: str = "viewer"


class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=14, max_length=512)


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


class ApplicationHealthCheck(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    url: str = Field(min_length=1, max_length=2048)
    expected_status: int = Field(default=200, ge=100, le=599)
    body_contains: str = Field(default="", max_length=128)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    verify_tls: bool = True


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
    health_gate_enabled: bool = False
    health_gate_require_telemetry: bool = True
    health_cpu_max_percent: float = Field(default=95.0, ge=1.0, le=100.0)
    health_cpu_max_delta: float = Field(default=40.0, ge=0.0, le=100.0)
    health_memory_max_percent: float = Field(default=95.0, ge=1.0, le=100.0)
    health_memory_max_delta: float = Field(default=20.0, ge=0.0, le=100.0)
    health_disk_min_free_percent: float = Field(default=5.0, ge=0.0, le=100.0)
    health_disk_max_free_drop: float = Field(default=10.0, ge=0.0, le=100.0)
    critical_services: List[str] = Field(default_factory=list, max_length=20)
    application_health_checks: List[ApplicationHealthCheck] = Field(default_factory=list, max_length=10)
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


class RemediationRescanRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class VulnerabilityStatusUpdate(BaseModel):
    status: str


class VulnerabilitySlaExceptionCreate(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)
    expires_at: datetime


class VulnerabilitySlaExceptionRevoke(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)


class RingAdvance(BaseModel):
    target_percent: int = Field(ge=1, le=100)
    override_health_gate: bool = False


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class AgentUpdateRolloutCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=1000)
    target_tag: str = Field(default="", max_length=128)
    ring_percent: int = Field(default=10, ge=1, le=100)
    expected_version: str = Field(
        min_length=5,
        max_length=64,
        pattern=r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class AgentUpdateActivationRequest(BaseModel):
    expected_version: str = Field(
        min_length=5,
        max_length=64,
        pattern=r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class AgentUpdateQuarantineClearRequest(BaseModel):
    expected_version: str = Field(
        min_length=5,
        max_length=64,
        pattern=r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_risk: bool = False


class AgentMtlsBindRequest(BaseModel):
    fingerprint: str = Field(min_length=40, max_length=95)
    reason: str = Field(min_length=5, max_length=500)


class TagUpdate(BaseModel):
    tags: List[str]
