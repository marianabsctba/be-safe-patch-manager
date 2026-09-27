#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests

DEFAULT_CONFIG = Path(os.getenv("PATCH_AGENT_CONFIG", "/etc/patch-manager/agent.json" if os.name != "nt" else r"C:\ProgramData\PatchManager\agent.json"))
PKG_RE = re.compile(r"^[A-Za-z0-9._+:-]{1,128}$")
KB_RE = re.compile(r"^KB\d{4,10}$", re.I)
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")

AGENT_VERSION = "0.13.0"
AGENT_PROTOCOL = 2
AGENT_CAPABILITIES = (
    "scan_updates",
    "install_updates",
    "job_leases_v1",
    "health_telemetry_v1",
    "rollback_checkpoint_v1",
    "rollback_restore_v1",
    "mtls_client_v1",
)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def run(cmd, timeout=1800, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return {"returncode": p.returncode, "stdout": p.stdout[-20000:], "stderr": p.stderr[-20000:]}


def load_config(path: Path):
    if not path.exists():
        raise SystemExit(f"Config não encontrada: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_config(path: Path, cfg):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:
        pass


def tls_request_options(cfg):
    client_cert = str(cfg.get("client_cert") or "").strip()
    client_key = str(cfg.get("client_key") or "").strip()
    ca_cert = str(cfg.get("ca_cert") or "").strip()

    if bool(client_cert) != bool(client_key):
        raise RuntimeError("client_cert and client_key must be configured together")

    cert = None
    if client_cert and client_key:
        if not Path(client_cert).is_file():
            raise RuntimeError(f"mTLS client certificate not found: {client_cert}")
        if not Path(client_key).is_file():
            raise RuntimeError(f"mTLS client key not found: {client_key}")
        cert = (client_cert, client_key)

    verify = cfg.get("tls_verify", True)
    if ca_cert:
        if not Path(ca_cert).is_file():
            raise RuntimeError(f"TLS CA certificate not found: {ca_cert}")
        verify = ca_cert

    if verify is False:
        raise RuntimeError("tls_verify=false is not allowed")

    return {"verify": verify, "cert": cert}


def api(cfg, method, path, *, json_body=None, headers=None, timeout=60):
    url = cfg["server_url"].rstrip("/") + path
    if not url.lower().startswith("https://"):
        raise RuntimeError("server_url must use https://")

    h = {"User-Agent": f"PatchManagerAgent/{AGENT_VERSION}"}
    if headers:
        h.update(headers)

    tls = tls_request_options(cfg)
    r = requests.request(
        method,
        url,
        json=json_body,
        headers=h,
        timeout=timeout,
        verify=tls["verify"],
        cert=tls["cert"],
    )
    r.raise_for_status()
    return r.json() if r.content else {}


def os_info():
    family = "windows" if os.name == "nt" else "linux"
    return {
        "hostname": socket.gethostname(),
        "os_family": family,
        "os_name": platform.system(),
        "os_version": platform.platform(),
        "arch": platform.machine(),
        "ip_address": get_ip(),
    }


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""



def _loopback_health_url(url):
    try:
        parsed = urlparse(str(url or ""))
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    host = parsed.hostname.lower()
    if host == "localhost":
        return parsed
    try:
        if ipaddress.ip_address(host).is_loopback:
            return parsed
    except ValueError:
        pass
    return None


def collect_service_health(names):
    results = {}
    for raw_name in names or []:
        name = str(raw_name or "").strip()
        if not SERVICE_RE.fullmatch(name):
            results[name or "<invalid>"] = {
                "healthy": False,
                "status": "invalid_name",
            }
            continue

        if os.name == "nt":
            try:
                service = psutil.win_service_get(name)
                status = str(service.status() or "unknown").lower()
                results[name] = {
                    "healthy": status == "running",
                    "status": status,
                }
            except Exception as exc:
                results[name] = {
                    "healthy": False,
                    "status": "unavailable",
                    "error": str(exc)[:200],
                }
            continue

        systemctl = shutil.which("systemctl")
        if not systemctl:
            results[name] = {
                "healthy": False,
                "status": "unsupported",
                "error": "systemctl unavailable",
            }
            continue

        try:
            rr = run([systemctl, "is-active", name], timeout=10)
            status = str(rr.get("stdout") or "").strip().lower() or "unknown"
            results[name] = {
                "healthy": rr.get("returncode") == 0 and status == "active",
                "status": status,
            }
        except Exception as exc:
            results[name] = {
                "healthy": False,
                "status": "error",
                "error": str(exc)[:200],
            }
    return results


def collect_application_health(checks):
    results = {}
    for index, raw in enumerate(checks or []):
        check = raw if isinstance(raw, dict) else {}
        name = str(check.get("name") or f"check-{index + 1}")[:64]
        url = str(check.get("url") or "")
        parsed = _loopback_health_url(url)
        if not parsed:
            results[name] = {
                "healthy": False,
                "status_code": None,
                "latency_ms": None,
                "error": "health URL rejected: loopback HTTP(S) only",
            }
            continue

        try:
            expected_status = int(check.get("expected_status", 200))
        except (TypeError, ValueError):
            expected_status = 200
        expected_status = min(599, max(100, expected_status))

        try:
            timeout = int(check.get("timeout_seconds", 5))
        except (TypeError, ValueError):
            timeout = 5
        timeout = min(30, max(1, timeout))
        body_contains = str(check.get("body_contains") or "")[:128]
        verify_tls = bool(check.get("verify_tls", True))

        started = time.perf_counter()
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=verify_tls,
            )
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            body_ok = not body_contains or body_contains in response.text[:65536]
            healthy = response.status_code == expected_status and body_ok
            results[name] = {
                "healthy": healthy,
                "status_code": response.status_code,
                "latency_ms": latency_ms,
                "body_match": body_ok,
            }
        except Exception as exc:
            results[name] = {
                "healthy": False,
                "status_code": None,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "error": str(exc)[:200],
            }
    return results


def collect_health(policy=None):
    policy = policy if isinstance(policy, dict) else {}
    errors = []

    cpu_percent = None
    try:
        samples = [psutil.cpu_percent(interval=0.2) for _ in range(3)]
        cpu_percent = round(sum(samples) / len(samples), 1)
    except Exception as exc:
        errors.append("cpu: " + str(exc)[:160])

    memory_percent = None
    try:
        memory_percent = round(float(psutil.virtual_memory().percent), 1)
    except Exception as exc:
        errors.append("memory: " + str(exc)[:160])

    root = os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"
    disk = {"path": root, "free_percent": None, "free_bytes": None}
    try:
        usage = psutil.disk_usage(root)
        free_percent = (float(usage.free) / float(usage.total) * 100.0) if usage.total else 0.0
        disk = {
            "path": root,
            "free_percent": round(free_percent, 1),
            "free_bytes": int(usage.free),
        }
    except Exception as exc:
        errors.append("disk: " + str(exc)[:160])

    services = collect_service_health(policy.get("critical_services") or [])
    applications = collect_application_health(policy.get("application_checks") or [])

    return {
        "schema": 1,
        "collected_at": utcnow(),
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "disk": disk,
        "services": services,
        "applications": applications,
        "policy_enabled": bool(policy.get("enabled", False)),
        "errors": errors,
    }


def active_health_policy(cfg):
    policy = cfg.get("_active_health_policy")
    if not isinstance(policy, dict):
        return {}
    try:
        expires_at = float(cfg.get("_active_health_policy_expires_at") or 0)
    except (TypeError, ValueError):
        expires_at = 0
    if expires_at and expires_at <= time.time():
        return {}
    return policy


def persist_health_policy(cfg, cfg_path, policy):
    policy = policy if isinstance(policy, dict) else {}
    if policy.get("enabled"):
        try:
            ttl = int(policy.get("policy_ttl_seconds", 86400))
        except (TypeError, ValueError):
            ttl = 86400
        ttl = min(604800, max(3600, ttl))
        cfg["_active_health_policy"] = policy
        cfg["_active_health_policy_expires_at"] = int(time.time()) + ttl
    else:
        cfg.pop("_active_health_policy", None)
        cfg.pop("_active_health_policy_expires_at", None)

    if cfg_path:
        save_config(Path(cfg_path), cfg)


def inventory():
    info = os_info()
    info.update({
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "boot_time_hint": None,
        "agent": {
            "version": AGENT_VERSION,
            "protocol": AGENT_PROTOCOL,
            "capabilities": list(AGENT_CAPABILITIES),
        },
        "rollback": rollback_capability(),
    })
    if os.name == "nt":
        ps = r'''$ErrorActionPreference='SilentlyContinue';
$os=Get-CimInstance Win32_OperatingSystem;
$cs=Get-CimInstance Win32_ComputerSystem;
[pscustomobject]@{caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;last_boot=$os.LastBootUpTime;ram_bytes=[int64]$cs.TotalPhysicalMemory}|ConvertTo-Json -Compress'''
        rr = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=60)
        if rr["returncode"] == 0:
            try: info["windows"] = json.loads(rr["stdout"])
            except Exception: pass
    else:
        try:
            info["kernel"] = platform.release()
            if Path("/etc/os-release").exists():
                info["os_release"] = Path("/etc/os-release").read_text(errors="replace")[:8000]
        except Exception:
            pass
    return info



def windows_rollback_capability():
    ps = r'''$checkpoint=$null -ne (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue);
$restore=$false;
try{$null=[WMIClass]'\\.\root\default:SystemRestore';$restore=$true}catch{}
[pscustomobject]@{checkpoint_supported=[bool]$checkpoint;automatic_restore=[bool]($checkpoint -and $restore);method='windows_restore_point'}|ConvertTo-Json -Compress'''
    rr = run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps], timeout=30)
    if rr["returncode"] != 0:
        return {"checkpoint_supported":False,"automatic_restore":False,"method":"windows_restore_point","reason":"system restore capability unavailable"}
    try:
        data=json.loads(rr["stdout"].strip() or "{}")
        data["platform"]="windows"
        return data
    except Exception:
        return {"checkpoint_supported":False,"automatic_restore":False,"method":"windows_restore_point","reason":"capability probe failed","platform":"windows"}


def linux_rollback_capability():
    snapper = shutil.which("snapper")
    if snapper:
        rr = run([snapper,"get-config"], timeout=30)
        if rr["returncode"] == 0:
            return {
                "platform":"linux",
                "checkpoint_supported":True,
                "automatic_restore":False,
                "method":"snapper_snapshot",
                "reason":"snapper root configuration available",
            }
    fstype=""
    if shutil.which("findmnt"):
        rr=run(["findmnt","-n","-o","FSTYPE","/"], timeout=20)
        if rr["returncode"] == 0:
            fstype=rr["stdout"].strip()
    return {
        "platform":"linux",
        "checkpoint_supported":False,
        "automatic_restore":False,
        "method":"snapper_snapshot",
        "filesystem":fstype,
        "reason":"configure Snapper for managed Linux checkpoints" if fstype == "btrfs" else "no managed snapshot provider detected",
    }


def rollback_capability():
    return windows_rollback_capability() if os.name == "nt" else linux_rollback_capability()


def windows_create_restore_point(job_id):
    if not re.fullmatch(r"[A-Fa-f0-9-]{36}", str(job_id)):
        return {"status":"failed","method":"windows_restore_point","automatic_restore":False,"reason":"invalid job id"}
    desc = "Be Safe Patch " + str(job_id)[:12]
    desc_json = json.dumps(desc)
    ps = rf'''$ErrorActionPreference='Stop';
$desc={desc_json};
Checkpoint-Computer -Description $desc -RestorePointType 'MODIFY_SETTINGS';
$rp=Get-ComputerRestorePoint | Where-Object {{$_.Description -eq $desc}} | Sort-Object SequenceNumber | Select-Object -Last 1;
if(-not $rp){{throw 'restore point was not found after creation'}}
[pscustomobject]@{{status='created';method='windows_restore_point';automatic_restore=$true;sequence=[int]$rp.SequenceNumber;description=[string]$rp.Description;creation_time=[string]$rp.CreationTime}}|ConvertTo-Json -Compress'''
    rr=run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps], timeout=300)
    if rr["returncode"] != 0:
        return {"status":"failed","method":"windows_restore_point","automatic_restore":False,"reason":(rr["stderr"] or rr["stdout"] or "restore point creation failed")[-2000:]}
    try:
        return json.loads(rr["stdout"].strip() or "{}")
    except Exception:
        return {"status":"failed","method":"windows_restore_point","automatic_restore":False,"reason":"invalid restore point response"}


def linux_create_snapper_checkpoint(job_id):
    snapper=shutil.which("snapper")
    if not snapper:
        return {"status":"unsupported","method":"snapper_snapshot","automatic_restore":False,"reason":"snapper is not installed"}
    check=run([snapper,"get-config"], timeout=30)
    if check["returncode"] != 0:
        return {"status":"unsupported","method":"snapper_snapshot","automatic_restore":False,"reason":"snapper root configuration is unavailable"}
    desc="Be Safe Patch "+str(job_id)[:12]
    rr=run([snapper,"create","--type","single","--cleanup-algorithm","number","--description",desc,"--print-number"], timeout=300)
    if rr["returncode"] != 0:
        return {"status":"failed","method":"snapper_snapshot","automatic_restore":False,"reason":(rr["stderr"] or rr["stdout"] or "snapper snapshot failed")[-2000:]}
    number=rr["stdout"].strip().splitlines()[-1].strip() if rr["stdout"].strip() else ""
    return {
        "status":"created",
        "method":"snapper_snapshot",
        "automatic_restore":False,
        "snapshot_number":number,
        "description":desc,
        "manual_recovery_required":True,
    }


def create_rollback_checkpoint(job_id):
    return windows_create_restore_point(job_id) if os.name == "nt" else linux_create_snapper_checkpoint(job_id)


def windows_restore_checkpoint(payload):
    try:
        sequence=int(payload.get("restore_point_sequence"))
    except Exception as exc:
        raise RuntimeError("restore point sequence is invalid") from exc
    if sequence <= 0:
        raise RuntimeError("restore point sequence is invalid")
    ps = rf'''$ErrorActionPreference='Stop';
$seq={sequence};
$rp=Get-ComputerRestorePoint | Where-Object {{$_.SequenceNumber -eq $seq}} | Select-Object -First 1;
if(-not $rp){{throw 'restore point not found'}}
$sr=[WMIClass]'\\.\root\default:SystemRestore';
$r=$sr.Restore($seq);
if([int]$r.ReturnValue -ne 0){{throw ('SystemRestore.Restore returned '+[int]$r.ReturnValue)}}
shutdown.exe /r /t 120 /c "Be Safe Patch Manager: reinicialização para concluir rollback" | Out-Null;
[pscustomobject]@{{restore_point_sequence=$seq;description=[string]$rp.Description;restore_return_value=[int]$r.ReturnValue;reboot_scheduled_seconds=120}}|ConvertTo-Json -Compress'''
    rr=run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps], timeout=120)
    if rr["returncode"] != 0:
        raise RuntimeError(rr["stderr"] or rr["stdout"] or "system restore failed")
    try:
        return json.loads(rr["stdout"].strip() or "{}")
    except Exception as exc:
        raise RuntimeError("invalid rollback response") from exc


def rollback_checkpoint(payload):
    method=str(payload.get("method") or "")
    if method != "windows_restore_point" or os.name != "nt":
        raise RuntimeError("automatic rollback is not supported for this checkpoint")
    return windows_restore_checkpoint(payload)


def windows_scan():
    ps = r'''$ErrorActionPreference='Stop';
$session=New-Object -ComObject Microsoft.Update.Session;
$searcher=$session.CreateUpdateSearcher();
$result=$searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'");
$out=@();
for($i=0;$i -lt $result.Updates.Count;$i++){
  $u=$result.Updates.Item($i);
  $kbs=@($u.KBArticleIDs | ForEach-Object { "KB$_" });
  $sev=if($u.MsrcSeverity){$u.MsrcSeverity}else{"unknown"};
  $out += [pscustomobject]@{id=$u.Identity.UpdateID;title=$u.Title;kb=$kbs;severity=$sev;reboot_behavior=[string]$u.InstallationBehavior.RebootBehavior}
}
$out|ConvertTo-Json -Compress -Depth 4'''
    rr = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=600)
    if rr["returncode"] != 0:
        raise RuntimeError(rr["stderr"] or rr["stdout"])
    raw = rr["stdout"].strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict): data = [data]
    return data


def windows_reboot_required():
    ps = r'''$p1=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired';
$p2=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending';
if($p1 -or $p2){'true'}else{'false'}'''
    rr = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
    return rr["stdout"].strip().lower() == "true"


def windows_install(packages, allow_reboot=False):
    requested = [x.upper() for x in packages if KB_RE.match(str(x).strip())]
    kb_json = json.dumps(requested)
    ps = rf'''$ErrorActionPreference='Stop';
$wanted=ConvertFrom-Json @'
{kb_json}
'@;
$session=New-Object -ComObject Microsoft.Update.Session;
$searcher=$session.CreateUpdateSearcher();
$r=$searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'");
$coll=New-Object -ComObject Microsoft.Update.UpdateColl;
$selected=@();
for($i=0;$i -lt $r.Updates.Count;$i++){{
  $u=$r.Updates.Item($i);
  $kbs=@($u.KBArticleIDs | ForEach-Object {{ "KB$_" }});
  $take=($wanted.Count -eq 0);
  foreach($kb in $kbs){{if($wanted -contains $kb){{$take=$true}}}}
  if($take){{
    if(-not $u.EulaAccepted){{$u.AcceptEula()}}
    [void]$coll.Add($u); $selected += [pscustomobject]@{{title=$u.Title;kb=$kbs}}
  }}
}}
if($coll.Count -eq 0){{[pscustomobject]@{{selected=@();result='nothing_to_do';reboot_required=$false}}|ConvertTo-Json -Compress -Depth 5; exit 0}}
$downloader=$session.CreateUpdateDownloader();$downloader.Updates=$coll;$d=$downloader.Download();
$installer=$session.CreateUpdateInstaller();$installer.Updates=$coll;$i=$installer.Install();
[pscustomobject]@{{selected=$selected;download_result=[int]$d.ResultCode;install_result=[int]$i.ResultCode;reboot_required=[bool]$i.RebootRequired}}|ConvertTo-Json -Compress -Depth 6'''
    rr = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=3600)
    if rr["returncode"] != 0:
        raise RuntimeError(rr["stderr"] or rr["stdout"])
    result = json.loads(rr["stdout"].strip() or "{}")
    if allow_reboot and result.get("reboot_required"):
        # Deliberately schedule rather than immediate restart to allow API result delivery.
        run(["shutdown.exe", "/r", "/t", "120", "/c", "Patch Manager: reinicialização necessária após atualização"], timeout=20)
        result["reboot_scheduled_seconds"] = 120
    return result


def linux_manager():
    for name in ("apt-get", "dnf", "yum"):
        p = subprocess.run(["sh", "-c", f"command -v {name}"], capture_output=True, text=True)
        if p.returncode == 0:
            return name
    return None


def linux_scan():
    mgr = linux_manager()
    if mgr == "apt-get":
        env = os.environ.copy(); env["LC_ALL"] = "C"
        run(["apt-get", "update", "-qq"], timeout=600, env=env)
        rr = run(["apt", "list", "--upgradable"], timeout=120, env=env)
        updates=[]
        for line in rr["stdout"].splitlines():
            if "/" not in line or line.startswith("Listing"):
                continue
            pkg=line.split("/",1)[0].strip()
            rest=line.split()
            updates.append({"id": pkg, "title": line.strip(), "package": pkg, "severity": "unknown", "version": rest[1] if len(rest)>1 else ""})
        return updates
    if mgr in {"dnf", "yum"}:
        rr = run([mgr, "-q", "check-update"], timeout=600)
        updates=[]
        for line in rr["stdout"].splitlines():
            parts=line.split()
            if len(parts)>=3 and PKG_RE.match(parts[0]):
                updates.append({"id":parts[0],"title":line.strip(),"package":parts[0],"severity":"unknown","version":parts[1]})
        return updates
    raise RuntimeError("Gerenciador suportado não encontrado (apt/dnf/yum)")


def linux_reboot_required():
    return Path("/var/run/reboot-required").exists()


def linux_install(packages, allow_reboot=False):
    mgr = linux_manager()
    safe = [str(x) for x in packages if PKG_RE.match(str(x))]
    env = os.environ.copy(); env["DEBIAN_FRONTEND"]="noninteractive"; env["LC_ALL"]="C"
    if mgr == "apt-get":
        run(["apt-get", "update", "-qq"], timeout=600, env=env)
        cmd = ["apt-get", "install", "-y", "--only-upgrade", *safe] if safe else ["apt-get", "upgrade", "-y"]
    elif mgr in {"dnf", "yum"}:
        cmd = [mgr, "upgrade", "-y", *safe] if safe else [mgr, "upgrade", "-y"]
    else:
        raise RuntimeError("Gerenciador suportado não encontrado")
    rr = run(cmd, timeout=3600, env=env)
    result={"manager":mgr,"packages":safe,"returncode":rr["returncode"],"stdout":rr["stdout"],"stderr":rr["stderr"],"reboot_required":linux_reboot_required()}
    if rr["returncode"] != 0:
        raise RuntimeError(rr["stderr"] or rr["stdout"])
    if allow_reboot and result["reboot_required"]:
        # Schedule at +2 minutes when systemd is available; otherwise report only.
        sched = run(["sh","-c","command -v shutdown >/dev/null && shutdown -r +2 'Patch Manager: reboot after updates'"], timeout=20)
        result["reboot_schedule_returncode"] = sched["returncode"]
    return result


def scan_updates():
    return windows_scan() if os.name == "nt" else linux_scan()


def reboot_required():
    return windows_reboot_required() if os.name == "nt" else linux_reboot_required()


def install_updates(payload):
    packages = payload.get("packages") or []
    allow_reboot = bool(payload.get("allow_reboot", False))
    return windows_install(packages, allow_reboot) if os.name == "nt" else linux_install(packages, allow_reboot)


def enroll(cfg, cfg_path):
    if cfg.get("agent_id") and cfg.get("agent_token"):
        # Migration/hardening: enrollment is one-time. Never retain its shared token
        # after an endpoint already has its own credentials.
        if "enrollment_token" in cfg:
            cfg.pop("enrollment_token", None)
            save_config(cfg_path, cfg)
        return

    enrollment_token = str(cfg.get("enrollment_token") or "").strip()
    if not enrollment_token:
        raise RuntimeError("enrollment_token is required for first enrollment")

    info = os_info(); info["tags"] = cfg.get("tags", [])
    data = api(
        cfg,
        "POST",
        "/api/agent/register",
        json_body=info,
        headers={"X-Enrollment-Token": enrollment_token},
    )
    cfg["agent_id"] = data["agent_id"]
    cfg["agent_token"] = data["agent_token"]
    cfg.pop("enrollment_token", None)
    save_config(cfg_path, cfg)
    print(f"Enrolled agent {cfg['agent_id']}")


def heartbeat(cfg, patches):
    current_inventory = inventory()
    current_inventory["health"] = collect_health(active_health_policy(cfg))
    return api(
        cfg,
        "POST",
        f"/api/agent/{cfg['agent_id']}/heartbeat",
        json_body={
            "inventory": current_inventory,
            "patch_scan": patches,
            "reboot_required": reboot_required(),
        },
        headers={"X-Agent-Token": cfg["agent_token"]},
    )


def send_job_result(cfg, job_id, status, claim_token, result=None, error="", started_at=None, finished_at=None):
    return api(
        cfg,
        "POST",
        f"/api/agent/{cfg['agent_id']}/jobs/{job_id}/result",
        json_body={
            "status":status,
            "claim_token":claim_token,
            "result":result or {},
            "error":error,
            "started_at":started_at,
            "finished_at":finished_at,
        },
        headers={"X-Agent-Token":cfg["agent_token"]},
    )


def renew_job_lease(cfg, job_id, claim_token):
    return api(
        cfg,
        "POST",
        f"/api/agent/{cfg['agent_id']}/jobs/{job_id}/lease",
        json_body={"claim_token":claim_token},
        headers={"X-Agent-Token":cfg["agent_token"]},
    )


def lease_keeper(cfg, job_id, claim_token, stop_event, interval):
    while not stop_event.wait(interval):
        try:
            renew_job_lease(cfg, job_id, claim_token)
        except Exception as exc:
            print(f"job lease renewal failed for {job_id}: {exc}", file=sys.stderr)


def execute_job(cfg, job, cfg_path=None):
    jid=job["id"]
    claim_token=str(job.get("claim_token") or "")
    if not claim_token:
        raise RuntimeError("job claim token is missing")

    started=utcnow()
    send_job_result(cfg,jid,"running",claim_token,started_at=started)

    lease_seconds=max(60,int(job.get("lease_seconds") or 300))
    renew_interval=max(15,min(60,lease_seconds // 3))
    lease_stop=threading.Event()
    lease_thread=threading.Thread(
        target=lease_keeper,
        args=(cfg,jid,claim_token,lease_stop,renew_interval),
        name=f"patch-lease-{jid[:8]}",
        daemon=True,
    )
    lease_thread.start()

    try:
        action=job["action"]
        if action == "scan_updates":
            result={"updates":scan_updates(),"reboot_required":reboot_required()}
        elif action == "install_updates":
            payload=job.get("payload") or {}
            health_policy = payload.get("health_policy") if isinstance(payload.get("health_policy"), dict) else {}
            persist_health_policy(cfg, cfg_path, health_policy)
            health_baseline = collect_health(health_policy) if health_policy.get("enabled") else {}

            checkpoint={"status":"disabled","method":"","automatic_restore":False,"reason":"rollback protection disabled"}
            if payload.get("prepare_rollback", True):
                checkpoint=create_rollback_checkpoint(jid)
                if payload.get("rollback_required", False) and checkpoint.get("status") != "created":
                    raise RuntimeError("rollback checkpoint required but unavailable: "+str(checkpoint.get("reason") or checkpoint.get("status")))
            result=install_updates(payload)
            result["rollback_checkpoint"]=checkpoint
            result["post_scan"] = scan_updates()
            if health_policy.get("enabled"):
                result["health_baseline"] = health_baseline
                result["health_post"] = collect_health(health_policy)
        elif action == "rollback_checkpoint":
            result=rollback_checkpoint(job.get("payload") or {})
        else:
            raise RuntimeError(f"Ação não permitida: {action}")
        send_job_result(cfg,jid,"success",claim_token,result=result,started_at=started,finished_at=utcnow())
    except Exception as e:
        send_job_result(cfg,jid,"failed",claim_token,error=str(e)[:10000],started_at=started,finished_at=utcnow())
    finally:
        lease_stop.set()
        lease_thread.join(timeout=5)


def loop(cfg, cfg_path):
    enroll(cfg,cfg_path)
    poll=max(15,int(cfg.get("poll_seconds",60)))
    scan_every=max(300,int(cfg.get("scan_every_seconds",1800)))
    last_scan=0; patches=[]
    while True:
        try:
            if time.time()-last_scan >= scan_every:
                patches=scan_updates(); heartbeat(cfg,patches); last_scan=time.time()
            jobs=api(cfg,"GET",f"/api/agent/{cfg['agent_id']}/jobs",headers={"X-Agent-Token":cfg["agent_token"]})
            for job in jobs:
                execute_job(cfg,job,cfg_path)
                try: patches=scan_updates(); heartbeat(cfg,patches); last_scan=time.time()
                except Exception as e: print(f"post-job heartbeat failed: {e}",file=sys.stderr)
        except KeyboardInterrupt:
            return
        except Exception as e:
            print(f"agent loop error: {e}",file=sys.stderr)
        time.sleep(poll)


def main():
    p=argparse.ArgumentParser(description="Patch Manager endpoint agent")
    p.add_argument("--config",default=str(DEFAULT_CONFIG))
    p.add_argument("--once",action="store_true",help="faz scan/heartbeat e processa no máximo um job")
    args=p.parse_args(); path=Path(args.config); cfg=load_config(path); enroll(cfg,path)
    if args.once:
        patches=scan_updates(); heartbeat(cfg,patches)
        jobs=api(cfg,"GET",f"/api/agent/{cfg['agent_id']}/jobs",headers={"X-Agent-Token":cfg["agent_token"]})
        for job in jobs[:1]: execute_job(cfg,job,path)
        return
    loop(cfg,path)


if __name__ == "__main__":
    main()
