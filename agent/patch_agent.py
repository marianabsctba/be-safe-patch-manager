#!/usr/bin/env python3
import argparse
import base64
import hashlib
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
import tempfile
import time
import zipfile
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

DEFAULT_CONFIG = Path(os.getenv("PATCH_AGENT_CONFIG", "/etc/patch-manager/agent.json" if os.name != "nt" else r"C:\ProgramData\PatchManager\agent.json"))
PKG_RE = re.compile(r"^[A-Za-z0-9._+:-]{1,128}$")
KB_RE = re.compile(r"^KB\d{4,10}$", re.I)
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")

AGENT_VERSION = "0.16.0"
AGENT_PROTOCOL = 2
AGENT_CAPABILITIES = (
    "scan_updates",
    "install_updates",
    "job_leases_v1",
    "health_telemetry_v1",
    "rollback_checkpoint_v1",
    "rollback_restore_v1",
    "mtls_client_v1",
    "signed_update_staging_v1",
    "signed_update_activation_v1",
    "signed_update_quarantine_v1",
)

UPDATE_PRODUCT = "be-safe-patch-agent"
UPDATE_MAX_BYTES = 50 * 1024 * 1024
UPDATE_ALLOWED_FILES = {"patch_agent.py", "requirements.txt"}
UPDATE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
UPDATE_FILENAME_RE = re.compile(r"^be-safe-patch-agent-[A-Za-z0-9.+-]+\.zip$")
UPDATE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _version_tuple(value):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def version_newer(candidate, current):
    candidate_tuple = _version_tuple(candidate)
    current_tuple = _version_tuple(current)
    return bool(candidate_tuple and current_tuple and candidate_tuple > current_tuple)


def canonical_update_manifest(manifest):
    return json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_update_manifest(manifest):
    if not isinstance(manifest, dict):
        raise RuntimeError("update manifest must be an object")
    if manifest.get("schema") != 1 or manifest.get("product") != UPDATE_PRODUCT:
        raise RuntimeError("unsupported update manifest")
    version = str(manifest.get("version") or "")
    if not UPDATE_VERSION_RE.fullmatch(version):
        raise RuntimeError("invalid update version")

    try:
        protocol = int(manifest.get("protocol"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("invalid update protocol") from exc
    if protocol < 1 or protocol > 1000:
        raise RuntimeError("update protocol outside allowed range")

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) > 64:
        raise RuntimeError("invalid update capabilities")
    for capability in capabilities:
        if not re.fullmatch(r"[a-z0-9_]{1,64}", str(capability or "")):
            raise RuntimeError("invalid update capability")

    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise RuntimeError("update artifact metadata missing")
    filename = str(artifact.get("filename") or "")
    if not UPDATE_FILENAME_RE.fullmatch(filename) or Path(filename).name != filename:
        raise RuntimeError("invalid update artifact filename")
    sha256 = str(artifact.get("sha256") or "").lower()
    if not UPDATE_SHA256_RE.fullmatch(sha256):
        raise RuntimeError("invalid update artifact SHA-256")
    try:
        size_bytes = int(artifact.get("size_bytes"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("invalid update artifact size") from exc
    if size_bytes < 1 or size_bytes > UPDATE_MAX_BYTES:
        raise RuntimeError("update artifact size outside allowed range")

    return manifest


def update_public_key(cfg):
    raw_path = str(cfg.get("update_public_key") or "").strip()
    if not raw_path:
        raise RuntimeError("update public key is not configured")
    path = Path(raw_path)
    if not path.is_file():
        raise RuntimeError(f"update public key not found: {path}")
    try:
        key = load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise RuntimeError("invalid update public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError("update public key must be Ed25519")
    return key


def verify_update_manifest(cfg, manifest, signature_b64):
    validate_update_manifest(manifest)
    try:
        signature = base64.b64decode(str(signature_b64 or ""), validate=True)
    except Exception as exc:
        raise RuntimeError("invalid update signature encoding") from exc
    if len(signature) != 64:
        raise RuntimeError("invalid update signature length")
    try:
        update_public_key(cfg).verify(signature, canonical_update_manifest(manifest))
    except InvalidSignature as exc:
        raise RuntimeError("update manifest signature verification failed") from exc
    return manifest, signature


def default_update_staging_dir():
    if os.name == "nt":
        return Path(r"C:\ProgramData\PatchManager\updates")
    return Path("/var/lib/patch-manager/updates")


def update_staging_dir(cfg):
    configured = str(cfg.get("update_staging_dir") or "").strip()
    return Path(configured) if configured else default_update_staging_dir()


def update_state_path(cfg):
    return update_staging_dir(cfg) / "state.json"


def read_update_state(cfg):
    if not str(cfg.get("update_public_key") or "").strip():
        return {"status": "disabled", "current_version": AGENT_VERSION}
    path = update_state_path(cfg)
    if not path.is_file():
        return {"status": "idle", "current_version": AGENT_VERSION}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"status": "error", "current_version": AGENT_VERSION, "last_error": "invalid local update state"}


def write_update_state(cfg, data):
    root = update_staging_dir(cfg)
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(root, 0o700)
    path = root / "state.json"
    tmp = root / "state.json.tmp"
    payload = {
        **data,
        "current_version": AGENT_VERSION,
    }
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    tmp.replace(path)
    return payload


def _update_headers(cfg):
    return {
        "User-Agent": f"PatchManagerAgent/{AGENT_VERSION}",
        "X-Agent-Token": cfg["agent_token"],
    }


def download_update_artifact(cfg, artifact_url, destination, expected_size):
    expected_prefix = f"/api/agent/{cfg['agent_id']}/updates/artifact/"
    if not str(artifact_url or "").startswith(expected_prefix):
        raise RuntimeError("update artifact URL is outside the allowed agent endpoint")

    url = cfg["server_url"].rstrip("/") + artifact_url
    tls = tls_request_options(cfg)
    with requests.get(
        url,
        headers=_update_headers(cfg),
        timeout=120,
        verify=tls["verify"],
        cert=tls["cert"],
        allow_redirects=False,
        stream=True,
    ) as response:
        response.raise_for_status()
        if 300 <= response.status_code < 400:
            raise RuntimeError("update artifact redirects are not allowed")

        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                advertised = int(content_length)
            except ValueError as exc:
                raise RuntimeError("invalid update artifact Content-Length") from exc
            if advertised != expected_size or advertised > UPDATE_MAX_BYTES:
                raise RuntimeError("update artifact Content-Length mismatch")

        written = 0
        digest = hashlib.sha256()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                written += len(chunk)
                if written > expected_size or written > UPDATE_MAX_BYTES:
                    raise RuntimeError("update artifact exceeded expected size")
                digest.update(chunk)
                handle.write(chunk)

    if written != expected_size:
        raise RuntimeError("update artifact size mismatch")
    return digest.hexdigest()


def inspect_update_archive(path):
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("update archive contains duplicate entries")
        if set(names) != UPDATE_ALLOWED_FILES:
            raise RuntimeError("update archive contains unexpected files")
        for info in archive.infolist():
            name = info.filename
            if Path(name).name != name or name.startswith(("/", "\\")) or ".." in Path(name).parts:
                raise RuntimeError("update archive contains unsafe paths")
            if info.is_dir() or info.file_size < 1 or info.file_size > 20 * 1024 * 1024:
                raise RuntimeError("update archive entry size is invalid")
    return True


def extract_staged_update(archive_path, target_dir):
    payload_dir = target_dir / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(payload_dir, 0o700)

    with zipfile.ZipFile(archive_path, "r") as archive:
        for name in sorted(UPDATE_ALLOWED_FILES):
            data = archive.read(name)
            target = payload_dir / name
            target.write_bytes(data)
            if os.name != "nt":
                os.chmod(target, 0o600)
    return payload_dir


def stage_signed_update(cfg):
    checked_at = utcnow()
    if not str(cfg.get("update_public_key") or "").strip():
        return write_update_state(cfg, {
            "status": "disabled",
            "checked_at": checked_at,
        })

    metadata = api(
        cfg,
        "GET",
        f"/api/agent/{cfg['agent_id']}/updates/latest",
        headers={"X-Agent-Token": cfg["agent_token"]},
        timeout=60,
    )

    if not metadata.get("enabled"):
        return write_update_state(cfg, {
            "status": "server_disabled",
            "checked_at": checked_at,
        })

    if not metadata.get("available"):
        return write_update_state(cfg, {
            "status": "current" if metadata.get("status") == "current" else "unavailable",
            "checked_at": checked_at,
            "latest_version": metadata.get("latest_version", ""),
            "last_error": metadata.get("error", ""),
        })

    manifest = metadata.get("manifest")
    signature_b64 = metadata.get("signature")
    manifest, signature = verify_update_manifest(cfg, manifest, signature_b64)
    version = manifest["version"]
    if not version_newer(version, AGENT_VERSION):
        raise RuntimeError("refusing non-upgrade agent release")

    activation_state = read_activation_state(cfg)
    if (
        activation_state.get("status") == "rolled_back"
        and str(activation_state.get("target_version") or "") == version
    ):
        return write_update_state(cfg, {
            "status": "quarantined",
            "checked_at": checked_at,
            "latest_version": version,
            "staged_version": version,
            "quarantined_version": version,
            "quarantined_at": activation_state.get("rolled_back_at") or utcnow(),
            "quarantine_reason": activation_state.get("rollback_reason") or "watchdog rollback",
            "activation": "blocked_after_rollback",
        })

    artifact = manifest["artifact"]
    artifact_url = str(metadata.get("artifact_url") or "")
    expected_url = (
        f"/api/agent/{cfg['agent_id']}/updates/artifact/"
        f"{artifact['filename']}"
    )
    if artifact_url != expected_url:
        raise RuntimeError("update artifact URL does not match signed manifest")

    root = update_staging_dir(cfg)
    target_dir = root / version
    target_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(target_dir, 0o700)

    archive_path = target_dir / artifact["filename"]
    temporary = target_dir / (artifact["filename"] + ".tmp")
    temporary.unlink(missing_ok=True)

    try:
        actual_sha256 = download_update_artifact(
            cfg,
            artifact_url,
            temporary,
            int(artifact["size_bytes"]),
        )
        if actual_sha256 != artifact["sha256"]:
            raise RuntimeError("update artifact SHA-256 mismatch")
        inspect_update_archive(temporary)
        temporary.replace(archive_path)
        if os.name != "nt":
            os.chmod(archive_path, 0o600)

        extract_staged_update(archive_path, target_dir)
        (target_dir / "agent-release.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (target_dir / "agent-release.sig").write_bytes(signature)
        if os.name != "nt":
            os.chmod(target_dir / "agent-release.json", 0o600)
            os.chmod(target_dir / "agent-release.sig", 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    return write_update_state(cfg, {
        "status": "staged",
        "checked_at": checked_at,
        "staged_at": utcnow(),
        "staged_version": version,
        "artifact_sha256": artifact["sha256"],
        "artifact_filename": artifact["filename"],
        "activation": "manual",
    })


def safe_stage_signed_update(cfg):
    try:
        return stage_signed_update(cfg)
    except Exception as exc:
        return write_update_state(cfg, {
            "status": "error",
            "checked_at": utcnow(),
            "last_error": str(exc)[:500],
        })



def agent_base_dir(cfg):
    configured = str(cfg.get("agent_base_dir") or "").strip()
    return Path(configured) if configured else Path("/opt/patch-manager-agent")


def activation_state_path(cfg):
    configured = str(cfg.get("activation_state_file") or "").strip()
    return Path(configured) if configured else Path("/var/lib/patch-manager/activation.json")


def read_activation_state(cfg):
    path = activation_state_path(cfg)
    if not path.is_file():
        return {"status": "idle", "current_version": AGENT_VERSION}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {
        "status": "error",
        "current_version": AGENT_VERSION,
        "last_error": "invalid activation state",
    }


def write_activation_state(cfg, data):
    path = activation_state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    tmp = path.with_name(path.name + ".tmp")
    payload = dict(data)
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    tmp.replace(path)
    return payload


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_staged_release(cfg, expected_version, allowed_statuses=None):
    state = read_update_state(cfg)
    allowed_statuses = set(allowed_statuses or {"staged"})
    if state.get("status") not in allowed_statuses:
        raise RuntimeError("agent update is not in an allowed staged state")
    if str(state.get("staged_version") or "") != str(expected_version or ""):
        raise RuntimeError("staged agent version does not match approved version")
    if not version_newer(expected_version, AGENT_VERSION):
        raise RuntimeError("approved agent version is not newer than current version")

    stage_dir = update_staging_dir(cfg) / expected_version
    manifest_path = stage_dir / "agent-release.json"
    signature_path = stage_dir / "agent-release.sig"
    if not manifest_path.is_file() or not signature_path.is_file():
        raise RuntimeError("staged release metadata is incomplete")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("staged release manifest is invalid") from exc

    signature = signature_path.read_bytes()
    manifest, _ = verify_update_manifest(
        cfg,
        manifest,
        base64.b64encode(signature).decode("ascii"),
    )
    if manifest["version"] != expected_version:
        raise RuntimeError("staged manifest version mismatch")

    artifact = manifest["artifact"]
    archive_path = stage_dir / artifact["filename"]
    if not archive_path.is_file():
        raise RuntimeError("staged agent archive is missing")
    if archive_path.stat().st_size != int(artifact["size_bytes"]):
        raise RuntimeError("staged agent archive size mismatch")
    if file_sha256(archive_path) != artifact["sha256"]:
        raise RuntimeError("staged agent archive SHA-256 mismatch")
    inspect_update_archive(archive_path)

    return {
        "state": state,
        "manifest": manifest,
        "signature": signature,
        "archive_path": archive_path,
        "stage_dir": stage_dir,
    }


def clear_update_quarantine(cfg, expected_version, reason, job_id):
    expected_version = str(expected_version or "").strip()
    reason = str(reason or "").strip()
    if not UPDATE_VERSION_RE.fullmatch(expected_version):
        raise RuntimeError("quarantine release version is invalid")
    if len(reason) < 5:
        raise RuntimeError("quarantine clear reason is required")

    activation_state = read_activation_state(cfg)
    if activation_state.get("status") != "rolled_back":
        raise RuntimeError("agent activation is not quarantined after rollback")
    if str(activation_state.get("target_version") or "") != expected_version:
        raise RuntimeError("quarantined version does not match requested release")

    release = verified_staged_release(
        cfg,
        expected_version,
        allowed_statuses={"quarantined"},
    )

    cleared_at = utcnow()
    write_activation_state(cfg, {
        **activation_state,
        "status": "quarantine_cleared",
        "quarantine_cleared_at": cleared_at,
        "quarantine_clear_reason": reason,
        "quarantine_clear_job_id": str(job_id or ""),
    })

    write_update_state(cfg, {
        **release["state"],
        "status": "staged",
        "staged_version": expected_version,
        "staged_at": release["state"].get("staged_at") or cleared_at,
        "quarantine_cleared_at": cleared_at,
        "quarantine_clear_reason": reason,
        "activation": "manual",
    })

    return {
        "status": "quarantine_cleared",
        "version": expected_version,
        "cleared_at": cleared_at,
    }


def _safe_live_release(cfg):
    base = agent_base_dir(cfg).resolve()
    releases = (base / "releases").resolve()
    current = base / "current"
    if not current.is_symlink():
        raise RuntimeError("managed release layout is not installed; run the v0.15+ installer once")

    try:
        target = current.resolve(strict=True)
        target.relative_to(releases)
    except Exception as exc:
        raise RuntimeError("current agent release symlink is invalid") from exc

    if not (target / "patch_agent.py").is_file() or not (target / "requirements.txt").is_file():
        raise RuntimeError("current agent release is incomplete")
    return base, releases, current, target


def _atomic_current_symlink(current, target_dir):
    relative_target = os.path.relpath(target_dir, current.parent)
    temporary = current.parent / (".current." + str(os.getpid()) + ".tmp")
    temporary.unlink(missing_ok=True)
    os.symlink(relative_target, temporary)
    os.replace(temporary, current)


def activate_staged_update(cfg, expected_version, job_id):
    if os.name == "nt":
        raise RuntimeError("automatic agent activation is not supported on Windows in v0.16")

    expected_version = str(expected_version or "").strip()
    if not UPDATE_VERSION_RE.fullmatch(expected_version):
        raise RuntimeError("approved agent version is invalid")

    release = verified_staged_release(cfg, expected_version)
    base, releases, current, live_release = _safe_live_release(cfg)
    previous_version = live_release.name

    if previous_version != AGENT_VERSION:
        raise RuntimeError("running agent version does not match managed current release")

    with zipfile.ZipFile(release["archive_path"], "r") as archive:
        new_requirements = archive.read("requirements.txt")
        new_agent = archive.read("patch_agent.py")

    current_requirements = (live_release / "requirements.txt").read_bytes()
    if new_requirements != current_requirements:
        raise RuntimeError(
            "automatic activation refuses dependency changes; redeploy the agent with the installer"
        )

    target_dir = releases / expected_version
    if target_dir.exists():
        expected_agent_sha = hashlib.sha256(new_agent).hexdigest()
        existing_agent = target_dir / "patch_agent.py"
        existing_requirements = target_dir / "requirements.txt"
        if (
            not existing_agent.is_file()
            or not existing_requirements.is_file()
            or hashlib.sha256(existing_agent.read_bytes()).hexdigest() != expected_agent_sha
            or existing_requirements.read_bytes() != new_requirements
        ):
            raise RuntimeError("target agent release directory already exists with different content")
    else:
        releases.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(releases, 0o755)

        temp_dir = Path(tempfile.mkdtemp(prefix=f".{expected_version}.", dir=str(releases)))
        try:
            (temp_dir / "patch_agent.py").write_bytes(new_agent)
            (temp_dir / "requirements.txt").write_bytes(new_requirements)
            (temp_dir / "agent-release.json").write_text(
                json.dumps(release["manifest"], ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (temp_dir / "agent-release.sig").write_bytes(release["signature"])

            for file_path in temp_dir.iterdir():
                os.chmod(file_path, 0o600)
            os.chmod(temp_dir / "patch_agent.py", 0o700)

            compile_result = run(
                [sys.executable, "-m", "py_compile", str(temp_dir / "patch_agent.py")],
                timeout=60,
            )
            if compile_result["returncode"] != 0:
                raise RuntimeError(
                    "new agent failed Python compile check: "
                    + (compile_result["stderr"] or compile_result["stdout"])[-1000:]
                )

            help_result = run(
                [sys.executable, str(temp_dir / "patch_agent.py"), "--help"],
                timeout=60,
            )
            if help_result["returncode"] != 0:
                raise RuntimeError(
                    "new agent failed startup preflight: "
                    + (help_result["stderr"] or help_result["stdout"])[-1000:]
                )

            os.replace(temp_dir, target_dir)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    switching = {
        "status": "switching",
        "job_id": str(job_id or ""),
        "previous_version": previous_version,
        "target_version": expected_version,
        "attempts": 0,
        "approved_at": utcnow(),
        "last_error": "",
    }
    write_activation_state(cfg, switching)

    try:
        _atomic_current_symlink(current, target_dir)
    except Exception as exc:
        write_activation_state(cfg, {
            **switching,
            "status": "aborted_before_switch",
            "last_error": str(exc)[:500],
            "aborted_at": utcnow(),
        })
        raise

    pending = {
        **switching,
        "status": "pending",
        "switched_at": utcnow(),
    }
    write_activation_state(cfg, pending)

    update_state = read_update_state(cfg)
    write_update_state(cfg, {
        **update_state,
        "status": "activating",
        "activation": "pending_restart",
        "target_version": expected_version,
        "previous_version": previous_version,
        "activation_job_id": str(job_id or ""),
    })

    return {
        "status": "activation_prepared",
        "target_version": expected_version,
        "previous_version": previous_version,
        "restart_required": True,
        "watchdog": "launcher",
    }


def confirm_pending_activation(cfg):
    if os.name == "nt":
        return False
    state = read_activation_state(cfg)
    if state.get("status") not in {"pending", "switching"}:
        return False
    if str(state.get("target_version") or "") != AGENT_VERSION:
        return False

    committed = {
        **state,
        "status": "committed",
        "committed_at": utcnow(),
        "confirmed_version": AGENT_VERSION,
        "last_error": "",
    }
    write_activation_state(cfg, committed)

    update_state = read_update_state(cfg)
    write_update_state(cfg, {
        **update_state,
        "status": "activated",
        "activation": "committed",
        "active_version": AGENT_VERSION,
        "activated_at": committed["committed_at"],
    })
    return True


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


def inventory(cfg=None):
    cfg = cfg if isinstance(cfg, dict) else {}
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
        "update": read_update_state(cfg),
        "activation": read_activation_state(cfg),
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
    current_inventory = inventory(cfg)
    current_inventory["health"] = collect_health(active_health_policy(cfg))
    response = api(
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
    confirm_pending_activation(cfg)
    return response


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

    restart_after_success = False
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
        elif action == "activate_agent_update":
            payload = job.get("payload") or {}
            result = activate_staged_update(
                cfg,
                str(payload.get("expected_version") or ""),
                jid,
            )
            restart_after_success = True
        elif action == "clear_agent_update_quarantine":
            payload = job.get("payload") or {}
            result = clear_update_quarantine(
                cfg,
                str(payload.get("expected_version") or ""),
                str(payload.get("approved_reason") or ""),
                jid,
            )
        else:
            raise RuntimeError(f"Ação não permitida: {action}")
        send_job_result(cfg,jid,"success",claim_token,result=result,started_at=started,finished_at=utcnow())
    except Exception as e:
        send_job_result(cfg,jid,"failed",claim_token,error=str(e)[:10000],started_at=started,finished_at=utcnow())
    finally:
        lease_stop.set()
        lease_thread.join(timeout=5)

    if restart_after_success:
        raise SystemExit(0)


def loop(cfg, cfg_path):
    enroll(cfg,cfg_path)
    poll=max(15,int(cfg.get("poll_seconds",60)))
    scan_every=max(300,int(cfg.get("scan_every_seconds",1800)))
    last_scan=0; patches=[]
    last_update_check=0
    update_every=max(900,int(cfg.get("update_check_seconds",21600)))
    while True:
        try:
            if str(cfg.get("update_public_key") or "").strip() and time.time()-last_update_check >= update_every:
                safe_stage_signed_update(cfg)
                last_update_check=time.time()
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
    p.add_argument("--check-update",action="store_true",help="verifica e prepara update assinado sem ativá-lo")
    args=p.parse_args(); path=Path(args.config); cfg=load_config(path); enroll(cfg,path)
    if args.check_update:
        state=safe_stage_signed_update(cfg)
        print(json.dumps(state,ensure_ascii=False,indent=2))
        return
    if args.once:
        if str(cfg.get("update_public_key") or "").strip():
            safe_stage_signed_update(cfg)
        patches=scan_updates(); heartbeat(cfg,patches)
        jobs=api(cfg,"GET",f"/api/agent/{cfg['agent_id']}/jobs",headers={"X-Agent-Token":cfg["agent_token"]})
        for job in jobs[:1]: execute_job(cfg,job,path)
        return
    loop(cfg,path)


if __name__ == "__main__":
    main()
