import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key


MANIFEST_NAME = "agent-release.json"
SIGNATURE_NAME = "agent-release.sig"
PRODUCT = "be-safe-patch-agent"
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
FILENAME_RE = re.compile(r"^be-safe-patch-agent-[A-Za-z0-9.+-]+\.zip$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CAPABILITY_RE = re.compile(r"^[a-z0-9_]{1,64}$")
SOURCE_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class AgentReleaseError(RuntimeError):
    pass


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_file():
        raise AgentReleaseError(f"agent update public key not found: {path}")
    try:
        key = load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise AgentReleaseError("invalid agent update public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AgentReleaseError("agent update public key must be Ed25519")
    return key


def public_key_id(key: Ed25519PublicKey) -> str:
    material = key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(material).hexdigest()


def validate_manifest(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        raise AgentReleaseError("agent release manifest must be an object")
    if manifest.get("schema") != 2:
        raise AgentReleaseError("unsupported agent release manifest schema")
    if manifest.get("product") != PRODUCT:
        raise AgentReleaseError("invalid agent release product")

    version = str(manifest.get("version") or "")
    if not VERSION_RE.fullmatch(version):
        raise AgentReleaseError("invalid agent release version")

    try:
        protocol = int(manifest.get("protocol"))
    except (TypeError, ValueError) as exc:
        raise AgentReleaseError("invalid agent release protocol") from exc
    if protocol < 1 or protocol > 1000:
        raise AgentReleaseError("agent release protocol is outside allowed range")

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) > 64:
        raise AgentReleaseError("invalid agent release capabilities")
    normalized_capabilities = []
    for item in capabilities:
        value = str(item or "").strip()
        if not CAPABILITY_RE.fullmatch(value):
            raise AgentReleaseError(f"invalid agent release capability: {value}")
        normalized_capabilities.append(value)
    if len(set(normalized_capabilities)) != len(normalized_capabilities):
        raise AgentReleaseError("agent release capabilities must be unique")

    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise AgentReleaseError("agent release artifact metadata is required")

    filename = str(artifact.get("filename") or "")
    if not FILENAME_RE.fullmatch(filename) or Path(filename).name != filename:
        raise AgentReleaseError("invalid agent release artifact filename")

    sha256 = str(artifact.get("sha256") or "").lower()
    if not SHA256_RE.fullmatch(sha256):
        raise AgentReleaseError("invalid agent release artifact SHA-256")

    try:
        size_bytes = int(artifact.get("size_bytes"))
    except (TypeError, ValueError) as exc:
        raise AgentReleaseError("invalid agent release artifact size") from exc
    if size_bytes < 1 or size_bytes > MAX_ARTIFACT_BYTES:
        raise AgentReleaseError("agent release artifact size is outside allowed range")

    generated_at = str(manifest.get("generated_at") or "")
    if not generated_at or len(generated_at) > 64:
        raise AgentReleaseError("invalid agent release generated_at")

    source_commit = str(manifest.get("source_commit") or "").strip().lower()
    if not SOURCE_COMMIT_RE.fullmatch(source_commit):
        raise AgentReleaseError("invalid or missing agent release source_commit")

    signing_key_id = str(manifest.get("signing_key_id") or "").strip().lower()
    if not KEY_ID_RE.fullmatch(signing_key_id):
        raise AgentReleaseError("invalid or missing agent release signing_key_id")

    return {
        **manifest,
        "version": version,
        "protocol": protocol,
        "capabilities": normalized_capabilities,
        "source_commit": source_commit,
        "signing_key_id": signing_key_id,
        "artifact": {
            **artifact,
            "filename": filename,
            "sha256": sha256,
            "size_bytes": size_bytes,
        },
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_signed_release(release_dir: Path, public_key_file: Path) -> dict:
    release_dir = release_dir.resolve()
    manifest_path = release_dir / MANIFEST_NAME
    signature_path = release_dir / SIGNATURE_NAME
    if not manifest_path.is_file() or not signature_path.is_file():
        raise AgentReleaseError("signed agent release is not published")

    try:
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentReleaseError("invalid agent release manifest JSON") from exc

    manifest = validate_manifest(raw_manifest)
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise AgentReleaseError("invalid Ed25519 signature length")

    key = _public_key(public_key_file)
    actual_key_id = public_key_id(key)
    if manifest["signing_key_id"] != actual_key_id:
        raise AgentReleaseError("agent release signing_key_id does not match trusted public key")

    try:
        key.verify(signature, canonical_manifest_bytes(manifest))
    except InvalidSignature as exc:
        raise AgentReleaseError("agent release manifest signature is invalid") from exc

    artifact_path = (release_dir / manifest["artifact"]["filename"]).resolve()
    try:
        artifact_path.relative_to(release_dir)
    except ValueError as exc:
        raise AgentReleaseError("agent release artifact escapes release directory") from exc

    if not artifact_path.is_file():
        raise AgentReleaseError("agent release artifact is missing")

    actual_size = artifact_path.stat().st_size
    if actual_size != manifest["artifact"]["size_bytes"]:
        raise AgentReleaseError("agent release artifact size mismatch")

    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != manifest["artifact"]["sha256"]:
        raise AgentReleaseError("agent release artifact SHA-256 mismatch")

    return {
        "manifest": manifest,
        "signature": signature,
        "artifact_path": artifact_path,
    }
