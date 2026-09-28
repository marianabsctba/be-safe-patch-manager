import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, REGISTRY, generate_latest
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func, text

from .database import SessionLocal
from .models import AdminUser, Agent, Campaign, IntegrationState, PatchJob, RemediationEvidence, VulnerabilityFinding


APP_VERSION = "0.23.0"


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, value)


AGENT_ONLINE_SECONDS = _env_int("AGENT_ONLINE_SECONDS", 300, minimum=60)
THREAT_INTEL_SYNC_INTERVAL = _env_int("THREAT_INTEL_SYNC_INTERVAL", 21600, minimum=300)
THREAT_INTEL_STALE_SECONDS = _env_int("THREAT_INTEL_STALE_SECONDS", max(3600, THREAT_INTEL_SYNC_INTERVAL * 2), minimum=300)
BACKUP_STATUS_FILE = Path(os.getenv("BACKUP_STATUS_FILE", "/runtime/backup-status.json"))

HTTP_REQUESTS = Counter(
    "patch_manager_http_requests_total",
    "HTTP requests handled by the Patch Manager.",
    ["method", "route", "status"],
)
HTTP_DURATION = Histogram(
    "patch_manager_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)


def utcnow():
    return datetime.now(timezone.utc)


def _as_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if template:
        return str(template)
    return "unmatched"


async def prometheus_http_middleware(request: Request, call_next):
    if request.url.path == "/metrics":
        return await call_next(request)

    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = _route_label(request)
        HTTP_REQUESTS.labels(request.method, route, str(status)).inc()
        HTTP_DURATION.labels(request.method, route).observe(time.perf_counter() - started)


def readiness_response():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        active_admins = db.query(AdminUser).filter(
            AdminUser.role == "admin",
            AdminUser.active.is_(True),
        ).count()
        if active_admins < 1:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "database": "ok", "active_admin": False},
            )
        return {
            "status": "ready",
            "database": "ok",
            "active_admin": True,
            "time": utcnow().isoformat(),
        }
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "error", "active_admin": False},
        )
    finally:
        db.close()


def metrics_response():
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)



def _version_tuple(value: str):
    import re
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _agent_compatibility_status(inventory: dict) -> str:
    runtime = inventory.get("agent") if isinstance(inventory.get("agent"), dict) else {}
    version = str(runtime.get("version") or "").strip()
    try:
        protocol = int(runtime.get("protocol") or 0)
    except (TypeError, ValueError):
        protocol = 0

    current = _version_tuple(version)
    minimum = _version_tuple(os.getenv("AGENT_MIN_VERSION", "0.13.0"))
    try:
        minimum_protocol = max(1, int(os.getenv("AGENT_MIN_PROTOCOL", "2")))
    except ValueError:
        minimum_protocol = 2

    if not version or not protocol:
        return "unknown"
    if current is None or minimum is None or current < minimum:
        return "outdated"
    if protocol < minimum_protocol:
        return "protocol_unsupported"
    return "supported"



def _backup_state():
    state = {
        "ok": 0.0,
        "timestamp": 0.0,
        "age": 0.0,
        "size": 0.0,
    }
    try:
        data = json.loads(BACKUP_STATUS_FILE.read_text(encoding="utf-8"))
        timestamp = float(data.get("epoch") or 0)
        if timestamp <= 0:
            return state
        state["ok"] = 1.0
        state["timestamp"] = timestamp
        state["age"] = max(0.0, time.time() - timestamp)
        state["size"] = float(data.get("size_bytes") or 0)
    except Exception:
        pass
    return state


class PatchManagerCollector:
    def collect(self):
        info = GaugeMetricFamily(
            "patch_manager_info",
            "Static Patch Manager build information.",
            labels=["version"],
        )
        info.add_metric([APP_VERSION], 1)
        yield info

        mtls_required = GaugeMetricFamily(
            "patch_manager_agent_mtls_required",
            "Whether agent mTLS is required by the backend.",
        )
        mtls_required.add_metric([], 1 if os.getenv("AGENT_MTLS_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"} else 0)
        yield mtls_required

        database_up = GaugeMetricFamily(
            "patch_manager_database_up",
            "Whether the application can query its database.",
        )

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            database_up.add_metric([], 1)

            agents = db.query(Agent).all()
            current = utcnow()
            cutoff = current.timestamp() - AGENT_ONLINE_SECONDS

            agents_by_os = {}
            online = 0
            mtls_bound = 0
            pending_updates = 0
            critical_updates = 0
            reboot_required = 0
            health_reporting = 0
            unhealthy_services = 0
            unhealthy_applications = 0
            health_collection_errors = 0
            compatibility_counts = {
                "supported": 0,
                "outdated": 0,
                "protocol_unsupported": 0,
                "unknown": 0,
            }
            update_counts = {}
            activation_counts = {}

            for agent in agents:
                family = (agent.os_family or "unknown").lower()
                agents_by_os[family] = agents_by_os.get(family, 0) + 1
                seen = _as_utc(agent.last_seen)
                if seen and seen.timestamp() >= cutoff:
                    online += 1
                if agent.client_cert_fingerprint:
                    mtls_bound += 1
                pending_updates += int(agent.pending_updates or 0)
                critical_updates += int(agent.critical_updates or 0)
                reboot_required += 1 if agent.reboot_required else 0

                try:
                    inventory = json.loads(agent.inventory_json or "{}")
                except Exception:
                    inventory = {}
                compatibility_status = _agent_compatibility_status(inventory)
                compatibility_counts[compatibility_status] = compatibility_counts.get(compatibility_status, 0) + 1
                update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}
                update_status = str(update_state.get("status") or "unknown")
                update_counts[update_status] = update_counts.get(update_status, 0) + 1
                activation_state = inventory.get("activation") if isinstance(inventory.get("activation"), dict) else {}
                activation_status = str(activation_state.get("status") or "idle")
                activation_counts[activation_status] = activation_counts.get(activation_status, 0) + 1
                health = inventory.get("health") if isinstance(inventory.get("health"), dict) else {}
                if health:
                    health_reporting += 1
                    health_collection_errors += len(health.get("errors") or [])
                    services = health.get("services") if isinstance(health.get("services"), dict) else {}
                    applications = health.get("applications") if isinstance(health.get("applications"), dict) else {}
                    unhealthy_services += sum(
                        1 for item in services.values()
                        if isinstance(item, dict) and item.get("healthy") is False
                    )
                    unhealthy_applications += sum(
                        1 for item in applications.values()
                        if isinstance(item, dict) and item.get("healthy") is False
                    )

            agent_family = GaugeMetricFamily(
                "patch_manager_agents",
                "Managed agents by operating-system family.",
                labels=["os_family"],
            )
            for family, count in sorted(agents_by_os.items()):
                agent_family.add_metric([family], count)
            yield agent_family

            compatibility = GaugeMetricFamily(
                "patch_manager_agent_compatibility",
                "Managed agents by compatibility state.",
                labels=["status"],
            )
            for status, count in sorted(compatibility_counts.items()):
                compatibility.add_metric([status], count)
            yield compatibility

            enforcement = GaugeMetricFamily(
                "patch_manager_agent_compatibility_enforced",
                "Whether incompatible agents are prevented from claiming jobs.",
            )
            enforcement.add_metric(
                [],
                1 if os.getenv("AGENT_ENFORCE_COMPATIBILITY", "").strip().lower() in {"1", "true", "yes", "on"} else 0,
            )
            yield enforcement

            update_state_metric = GaugeMetricFamily(
                "patch_manager_agent_update_state",
                "Managed agents by signed update staging state.",
                labels=["status"],
            )
            for status, count in sorted(update_counts.items()):
                update_state_metric.add_metric([status], count)
            yield update_state_metric

            update_distribution = GaugeMetricFamily(
                "patch_manager_agent_update_distribution_enabled",
                "Whether signed agent release distribution is enabled.",
            )
            update_distribution.add_metric(
                [],
                1 if os.getenv("AGENT_UPDATE_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"} else 0,
            )
            yield update_distribution

            activation_state_metric = GaugeMetricFamily(
                "patch_manager_agent_activation_state",
                "Managed agents by self-update activation state.",
                labels=["status"],
            )
            for status, count in sorted(activation_counts.items()):
                activation_state_metric.add_metric([status], count)
            yield activation_state_metric

            for name, description, value in [
                ("patch_manager_agents_online", "Agents seen inside the online threshold.", online),
                ("patch_manager_agents_offline", "Agents outside the online threshold.", max(0, len(agents) - online)),
                ("patch_manager_agents_mtls_bound", "Agents bound to a client certificate.", mtls_bound),
                ("patch_manager_pending_updates", "Total pending updates reported by agents.", pending_updates),
                ("patch_manager_critical_updates", "Total critical/security updates reported by agents.", critical_updates),
                ("patch_manager_reboot_required_agents", "Agents reporting reboot required.", reboot_required),
                ("patch_manager_health_telemetry_agents", "Agents currently reporting health telemetry.", health_reporting),
                ("patch_manager_health_services_unhealthy", "Critical service checks currently unhealthy.", unhealthy_services),
                ("patch_manager_health_applications_unhealthy", "Application health checks currently unhealthy.", unhealthy_applications),
                ("patch_manager_health_collection_errors", "Current health telemetry collection errors reported by agents.", health_collection_errors),
            ]:
                metric = GaugeMetricFamily(name, description)
                metric.add_metric([], value)
                yield metric

            approval_pending = 0
            approval_expiring = 0
            approval_expired = 0
            approval_invalidated = 0
            current_time = utcnow()

            activation_jobs = db.query(PatchJob).filter(
                PatchJob.action == "activate_agent_update"
            ).all()
            for job in activation_jobs:
                if job.status == "skipped" and str(job.error or "").startswith(
                    "agent update authorization invalidated:"
                ):
                    approval_invalidated += 1
                    continue
                if job.status != "pending":
                    continue

                approval_pending += 1
                try:
                    payload = json.loads(job.payload_json or "{}")
                except Exception:
                    payload = {}
                expiry_text = str(payload.get("approval_expires_at") or "")
                if not expiry_text:
                    approval_expired += 1
                    continue
                try:
                    expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                except ValueError:
                    approval_expired += 1
                    continue

                seconds_left = (expiry - current_time).total_seconds()
                if seconds_left <= 0:
                    approval_expired += 1
                elif seconds_left <= 300:
                    approval_expiring += 1

            for name, description, value in [
                (
                    "patch_manager_agent_update_approvals_pending",
                    "Pending agent-update activation approvals.",
                    approval_pending,
                ),
                (
                    "patch_manager_agent_update_approvals_expiring",
                    "Pending agent-update approvals expiring within five minutes.",
                    approval_expiring,
                ),
                (
                    "patch_manager_agent_update_approvals_expired",
                    "Pending agent-update approvals that are already expired.",
                    approval_expired,
                ),
                (
                    "patch_manager_agent_update_authorizations_invalidated",
                    "Agent-update activation jobs invalidated before claim.",
                    approval_invalidated,
                ),
            ]:
                metric = GaugeMetricFamily(name, description)
                metric.add_metric([], value)
                yield metric

            jobs = GaugeMetricFamily(
                "patch_manager_jobs",
                "Patch jobs by current status.",
                labels=["status"],
            )
            for status, count in db.query(PatchJob.status, func.count(PatchJob.id)).group_by(PatchJob.status).all():
                jobs.add_metric([str(status or "unknown")], count)
            yield jobs

            campaigns = GaugeMetricFamily(
                "patch_manager_campaigns",
                "Campaigns by current status.",
                labels=["status"],
            )
            for status, count in db.query(Campaign.status, func.count(Campaign.id)).group_by(Campaign.status).all():
                campaigns.add_metric([str(status or "unknown")], count)
            yield campaigns

            vulnerabilities = GaugeMetricFamily(
                "patch_manager_vulnerabilities",
                "Vulnerability findings by status and severity.",
                labels=["status", "severity"],
            )
            vuln_rows = db.query(
                VulnerabilityFinding.status,
                VulnerabilityFinding.severity,
                func.count(VulnerabilityFinding.id),
            ).group_by(
                VulnerabilityFinding.status,
                VulnerabilityFinding.severity,
            ).all()
            for status, severity, count in vuln_rows:
                vulnerabilities.add_metric(
                    [str(status or "unknown"), str(severity or "unknown").lower()],
                    count,
                )
            yield vulnerabilities

            remediation = GaugeMetricFamily(
                "patch_manager_remediation_evidence",
                "Remediation evidence records by lifecycle status.",
                labels=["status"],
            )
            for status, count in db.query(
                RemediationEvidence.status,
                func.count(RemediationEvidence.id),
            ).group_by(RemediationEvidence.status).all():
                remediation.add_metric([str(status or "unknown")], count)
            yield remediation

            greenbone = db.get(IntegrationState, "greenbone")
            enabled = 1 if greenbone and greenbone.enabled else 0
            sync_ok = 1 if greenbone and greenbone.status == "ok" else 0
            last_success = _as_utc(greenbone.last_success_at) if greenbone else None

            for name, description, value in [
                ("patch_manager_greenbone_enabled", "Whether Greenbone integration is enabled.", enabled),
                ("patch_manager_greenbone_sync_ok", "Whether the latest Greenbone integration state is OK.", sync_ok),
                (
                    "patch_manager_greenbone_last_success_timestamp_seconds",
                    "Unix timestamp of the latest successful Greenbone sync.",
                    last_success.timestamp() if last_success else 0,
                ),
            ]:
                metric = GaugeMetricFamily(name, description)
                metric.add_metric([], value)
                yield metric

            threat_intel = db.get(IntegrationState, "threat_intel")
            threat_enabled = 1 if threat_intel and threat_intel.enabled else 0
            threat_healthy = 1 if threat_intel and threat_intel.status in {"ok", "degraded"} else 0
            threat_degraded = 1 if threat_intel and threat_intel.status == "degraded" else 0
            threat_last_success = _as_utc(threat_intel.last_success_at) if threat_intel else None
            threat_age = max(0.0, (current - threat_last_success).total_seconds()) if threat_last_success else 0.0
            threat_stale = 1 if threat_enabled and (not threat_last_success or threat_age > THREAT_INTEL_STALE_SECONDS) else 0

            for name, description, value in [
                ("patch_manager_threat_intel_enabled", "Whether EPSS/KEV enrichment is enabled.", threat_enabled),
                ("patch_manager_threat_intel_sync_healthy", "Whether the latest threat-intel sync is usable.", threat_healthy),
                ("patch_manager_threat_intel_degraded", "Whether only part of the configured threat-intel sources succeeded.", threat_degraded),
                ("patch_manager_threat_intel_stale", "Whether threat-intel data is older than the configured freshness threshold.", threat_stale),
                ("patch_manager_threat_intel_age_seconds", "Age in seconds of the latest usable threat-intel sync.", threat_age),
                (
                    "patch_manager_threat_intel_last_success_timestamp_seconds",
                    "Unix timestamp of the latest usable threat-intel sync.",
                    threat_last_success.timestamp() if threat_last_success else 0,
                ),
            ]:
                metric = GaugeMetricFamily(name, description)
                metric.add_metric([], value)
                yield metric

        except Exception:
            database_up.add_metric([], 0)
        finally:
            db.close()

        yield database_up

        backup = _backup_state()
        for name, description, value in [
            ("patch_manager_backup_status", "Whether a successful backup status record is available.", backup["ok"]),
            (
                "patch_manager_backup_last_success_timestamp_seconds",
                "Unix timestamp of the latest successful PostgreSQL backup.",
                backup["timestamp"],
            ),
            ("patch_manager_backup_age_seconds", "Age of the latest successful PostgreSQL backup.", backup["age"]),
            ("patch_manager_backup_size_bytes", "Size of the latest successful PostgreSQL backup.", backup["size"]),
        ]:
            metric = GaugeMetricFamily(name, description)
            metric.add_metric([], value)
            yield metric


REGISTRY.register(PatchManagerCollector())
