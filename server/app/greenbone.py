import hashlib
import os
import re
from dataclasses import dataclass

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform


KB_RE = re.compile(r"\bKB\d{6,8}\b", re.I)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, value)


@dataclass(frozen=True)
class GreenboneConfig:
    enabled: bool
    transport: str
    hostname: str
    port: int
    socket_path: str
    username: str
    password: str
    cafile: str
    certfile: str
    keyfile: str
    key_password: str
    timeout: int
    interval_seconds: int
    result_filter: str
    task_filter: str
    report_id: str
    reconcile_absent: bool


def get_config() -> GreenboneConfig:
    return GreenboneConfig(
        enabled=env_bool("GREENBONE_ENABLED", False),
        transport=os.getenv("GREENBONE_TRANSPORT", "tls").strip().lower(),
        hostname=os.getenv("GREENBONE_HOST", "127.0.0.1").strip(),
        port=env_int("GREENBONE_PORT", 9390),
        socket_path=os.getenv("GREENBONE_SOCKET", "/run/gvmd/gvmd.sock").strip(),
        username=os.getenv("GREENBONE_USERNAME", "").strip(),
        password=os.getenv("GREENBONE_PASSWORD", ""),
        cafile=os.getenv("GREENBONE_CA_FILE", "").strip(),
        certfile=os.getenv("GREENBONE_CERT_FILE", "").strip(),
        keyfile=os.getenv("GREENBONE_KEY_FILE", "").strip(),
        key_password=os.getenv("GREENBONE_KEY_PASSWORD", ""),
        timeout=env_int("GREENBONE_TIMEOUT", 60),
        interval_seconds=env_int("GREENBONE_SYNC_INTERVAL", 900, minimum=60),
        result_filter=os.getenv("GREENBONE_RESULT_FILTER", "rows=-1 min_qod=70").strip(),
        task_filter=os.getenv("GREENBONE_TASK_FILTER", "rows=-1").strip(),
        report_id=os.getenv("GREENBONE_REPORT_ID", "").strip(),
        reconcile_absent=env_bool("GREENBONE_RECONCILE_ABSENT", False),
    )


def public_config(config: GreenboneConfig | None = None) -> dict:
    config = config or get_config()
    transport_ok = config.transport in {"tls", "unix"}
    endpoint_ok = bool(config.socket_path) if config.transport == "unix" else bool(config.hostname and config.port)
    credentials_ok = bool(config.username and config.password)
    return {
        "enabled": config.enabled,
        "configured": bool(transport_ok and endpoint_ok and credentials_ok),
        "transport": config.transport,
        "hostname": config.hostname if config.transport == "tls" else "",
        "port": config.port if config.transport == "tls" else None,
        "socket_path": config.socket_path if config.transport == "unix" else "",
        "username_configured": bool(config.username),
        "password_configured": bool(config.password),
        "interval_seconds": config.interval_seconds,
        "result_filter": config.result_filter,
        "task_filter": config.task_filter,
        "report_id_configured": bool(config.report_id),
        "reconcile_absent": config.reconcile_absent,
    }


def _connection(config: GreenboneConfig):
    if config.transport == "unix":
        return UnixSocketConnection(path=config.socket_path, timeout=config.timeout)
    if config.transport != "tls":
        raise RuntimeError("GREENBONE_TRANSPORT must be tls or unix")

    kwargs = {"hostname": config.hostname, "port": config.port, "timeout": config.timeout}
    if config.cafile:
        kwargs["cafile"] = config.cafile
    if config.certfile:
        kwargs["certfile"] = config.certfile
    if config.keyfile:
        kwargs["keyfile"] = config.keyfile
    if config.key_password:
        kwargs["password"] = config.key_password
    return TLSConnection(**kwargs)


def _text(element, path: str) -> str:
    value = element.findtext(path)
    return str(value or "").strip()


def _report_ids(gmp, config: GreenboneConfig):
    if config.report_id:
        return [{
            "task_id": "",
            "task_name": "",
            "task_status": "",
            "report_id": config.report_id,
        }]

    tasks = gmp.get_tasks(filter_string=config.task_filter or None)
    reports = []
    seen = set()
    for task in tasks.xpath("task"):
        task_id = str(task.get("id") or "")
        task_name = _text(task, "name")
        candidates = [
            task.find("last_report/report"),
            task.find("current_report/report"),
            task.find("last_report"),
            task.find("current_report"),
        ]
        report_id = ""
        for candidate in candidates:
            if candidate is not None and candidate.get("id"):
                report_id = str(candidate.get("id"))
                break
        if report_id and report_id not in seen:
            reports.append({
                "task_id": task_id,
                "task_name": task_name,
                "task_status": _text(task, "status"),
                "report_id": report_id,
            })
            seen.add(report_id)
    return reports


def _stable_external_id(task_id: str, host: str, port: str, oid: str, result_id: str) -> str:
    scope = task_id or "report"
    identity = "|".join([host, port, oid or result_id])
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{scope}:{digest}"


def _parse_result(result, report_id: str, task_id: str, task_name: str) -> dict:
    result_id = str(result.get("id") or "")
    host = _text(result, "host")
    port = _text(result, "port")
    nvt = result.find("nvt")
    oid = str(nvt.get("oid") or "") if nvt is not None else ""
    title = _text(result, "name")
    if not title and nvt is not None:
        title = _text(nvt, "name")

    severity_text = _text(result, "severity")
    if not severity_text and nvt is not None:
        severity_text = _text(nvt, "cvss_base")
    try:
        cvss = float(severity_text or 0)
    except ValueError:
        cvss = 0.0

    cves = set()
    refs = []
    if nvt is not None:
        for ref in nvt.xpath(".//refs/ref"):
            ref_type = str(ref.get("type") or "").strip().lower()
            ref_id = str(ref.get("id") or "").strip()
            if not ref_id:
                continue
            refs.append({"type": ref_type, "id": ref_id})
            if ref_type == "cve":
                cves.add(ref_id.upper())
        cve_text = _text(nvt, "cve")
        for token in re.split(r"[,\s]+", cve_text):
            if token.upper().startswith("CVE-"):
                cves.add(token.upper())

    solution = _text(nvt, "solution") if nvt is not None else ""
    description = _text(result, "description")
    patch_refs = set(KB_RE.findall(solution + " " + description))
    for ref in refs:
        patch_refs.update(KB_RE.findall(ref["id"]))

    threat = _text(result, "threat").lower()
    severity = threat if threat in {"critical", "high", "medium", "low", "log"} else ""
    qod = _text(result, "qod/value") or _text(result, "qod")

    return {
        "external_id": _stable_external_id(task_id, host, port, oid, result_id),
        "host": host,
        "ip_address": host if re.fullmatch(r"[0-9a-fA-F:.]+", host or "") else "",
        "cves": sorted(cves),
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "port": port,
        "solution": solution,
        "patch_refs": sorted({item.upper() for item in patch_refs}),
        "resolved": False,
        "raw": {
            "greenbone_result_id": result_id,
            "greenbone_report_id": report_id,
            "greenbone_task_id": task_id,
            "greenbone_task_name": task_name,
            "nvt_oid": oid,
            "qod": qod,
            "description": description[:4000],
        },
    }


def fetch_findings(config: GreenboneConfig | None = None) -> dict:
    config = config or get_config()
    if not public_config(config)["configured"]:
        raise RuntimeError("Greenbone integration is not fully configured")

    transform = EtreeCheckCommandTransform()
    connection = _connection(config)
    output = {"manager_version": "", "reports": [], "findings": []}

    try:
        with GMP(connection=connection, transform=transform) as gmp:
            gmp.authenticate(config.username, config.password)
            version = gmp.get_version()
            output["manager_version"] = _text(version, "version")

            reports = _report_ids(gmp, config)
            if not reports:
                raise RuntimeError("No Greenbone latest reports were found")

            for report in reports:
                response = gmp.get_results(
                    report_id=report["report_id"],
                    filter_string=config.result_filter or None,
                )
                parsed = [
                    _parse_result(
                        result,
                        report["report_id"],
                        report["task_id"],
                        report["task_name"],
                    )
                    for result in response.xpath("result")
                ]
                output["reports"].append({
                    **report,
                    "finding_count": len(parsed),
                    "external_ids": [item["external_id"] for item in parsed],
                })
                output["findings"].extend(parsed)
    except GvmError as exc:
        raise RuntimeError(f"Greenbone GMP error: {exc}") from exc

    return output



def start_task_rescan(task_id: str, config: GreenboneConfig | None = None) -> dict:
    config = config or get_config()
    if not public_config(config)["configured"]:
        raise RuntimeError("Greenbone integration is not fully configured")

    task_id = str(task_id or "").strip()
    if not task_id:
        raise RuntimeError("Greenbone task id is required for remediation rescan")

    transform = EtreeCheckCommandTransform()
    connection = _connection(config)

    try:
        with GMP(connection=connection, transform=transform) as gmp:
            gmp.authenticate(config.username, config.password)
            task = gmp.get_task(task_id)
            task_name = _text(task, "task/name") or _text(task, "name")
            before_status = _text(task, "task/status") or _text(task, "status")

            response = gmp.start_task(task_id)
            report_id = _text(response, "report_id")
            if not report_id:
                nodes = response.xpath(".//report_id")
                if nodes and nodes[0].text:
                    report_id = str(nodes[0].text).strip()

            if not report_id:
                raise RuntimeError("Greenbone did not return a report id for the started task")

            return {
                "task_id": task_id,
                "task_name": task_name,
                "previous_status": before_status,
                "report_id": report_id,
            }
    except GvmError as exc:
        raise RuntimeError(f"Greenbone GMP error while starting rescan: {exc}") from exc
