import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


ATTESTATION_SCHEMA = "be-safe-evidence-attestation/v1"
PRODUCT = "be-safe-patch-manager"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceAttestationError(RuntimeError):
    pass


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def public_key_id(key: Ed25519PublicKey) -> str:
    material = key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(material).hexdigest()


def _enabled() -> bool:
    return os.getenv("EVIDENCE_ATTESTATION_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _private_key(path: Path) -> Ed25519PrivateKey:
    if not path.is_file():
        raise EvidenceAttestationError(f"evidence attestation private key not found: {path}")
    try:
        key = load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise EvidenceAttestationError("invalid evidence attestation private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceAttestationError("evidence attestation private key must be Ed25519")
    return key


def _public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_file():
        raise EvidenceAttestationError(f"evidence attestation public key not found: {path}")
    try:
        key = load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise EvidenceAttestationError("invalid evidence attestation public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceAttestationError("evidence attestation public key must be Ed25519")
    return key


def build_evidence_attestation(
    *,
    pack_sha256: str,
    campaign_id: str,
    generated_at: str,
) -> dict | None:
    if not _enabled():
        return None

    digest = str(pack_sha256 or "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise EvidenceAttestationError("invalid pack SHA-256 for evidence attestation")

    private_path = Path(
        os.getenv(
            "EVIDENCE_ATTESTATION_PRIVATE_KEY_FILE",
            "/evidence-trust/evidence-attestation-private.pem",
        )
    )
    key = _private_key(private_path)
    issuer = os.getenv("EVIDENCE_ATTESTATION_ISSUER", "Be Safe Patch Manager").strip()
    if not issuer:
        raise EvidenceAttestationError("evidence attestation issuer cannot be empty")

    statement = {
        "schema": ATTESTATION_SCHEMA,
        "product": PRODUCT,
        "issuer": issuer[:255],
        "campaign_id": str(campaign_id),
        "pack_sha256": digest,
        "generated_at": str(generated_at),
        "signing_key_id": public_key_id(key.public_key()),
    }
    signature = key.sign(canonical_bytes(statement))

    return {
        "statement": statement,
        "signature": {
            "algorithm": "Ed25519",
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_evidence_attestation(
    attestation: dict | None,
    *,
    expected_pack_sha256: str,
    expected_campaign_id: str = "",
    public_key_file: str | Path | None = None,
) -> dict:
    if not attestation:
        return {
            "present": False,
            "status": "unsigned",
            "valid": None,
            "key_id": None,
            "issuer": None,
            "issues": [],
        }

    issues: list[str] = []
    if not isinstance(attestation, dict):
        return {
            "present": True,
            "status": "invalid",
            "valid": False,
            "key_id": None,
            "issuer": None,
            "issues": ["attestation must be an object"],
        }

    statement = attestation.get("statement")
    signature_block = attestation.get("signature")
    if not isinstance(statement, dict):
        issues.append("attestation statement is missing or invalid")
        statement = {}
    if not isinstance(signature_block, dict):
        issues.append("attestation signature block is missing or invalid")
        signature_block = {}

    if statement.get("schema") != ATTESTATION_SCHEMA:
        issues.append("unsupported evidence attestation schema")
    if statement.get("product") != PRODUCT:
        issues.append("invalid evidence attestation product")

    digest = str(statement.get("pack_sha256") or "").strip().lower()
    if digest != str(expected_pack_sha256 or "").strip().lower():
        issues.append("attestation pack SHA-256 does not match computed pack digest")

    campaign_id = str(statement.get("campaign_id") or "")
    if expected_campaign_id and campaign_id != str(expected_campaign_id):
        issues.append("attestation campaign_id does not match expected campaign")

    key_id = str(statement.get("signing_key_id") or "").strip().lower()
    if not SHA256_RE.fullmatch(key_id):
        issues.append("invalid evidence attestation signing_key_id")

    if signature_block.get("algorithm") != "Ed25519":
        issues.append("unsupported evidence attestation signature algorithm")
    if signature_block.get("encoding") != "base64":
        issues.append("unsupported evidence attestation signature encoding")

    try:
        signature = base64.b64decode(str(signature_block.get("value") or ""), validate=True)
    except Exception:
        signature = b""
        issues.append("invalid base64 evidence attestation signature")
    if signature and len(signature) != 64:
        issues.append("invalid Ed25519 evidence attestation signature length")

    if issues:
        return {
            "present": True,
            "status": "invalid",
            "valid": False,
            "key_id": key_id or None,
            "issuer": statement.get("issuer"),
            "statement": statement,
            "issues": issues,
        }

    path = Path(
        public_key_file
        or os.getenv(
            "EVIDENCE_ATTESTATION_PUBLIC_KEY_FILE",
            "/evidence-trust/evidence-attestation-public.pem",
        )
    )
    if not path.is_file():
        return {
            "present": True,
            "status": "unverified_trust_key_unavailable",
            "valid": None,
            "key_id": key_id,
            "issuer": statement.get("issuer"),
            "statement": statement,
            "issues": [],
        }

    try:
        key = _public_key(path)
    except EvidenceAttestationError as exc:
        return {
            "present": True,
            "status": "invalid_trust_key",
            "valid": False,
            "key_id": key_id,
            "issuer": statement.get("issuer"),
            "statement": statement,
            "issues": [str(exc)],
        }

    actual_key_id = public_key_id(key)
    if actual_key_id != key_id:
        return {
            "present": True,
            "status": "wrong_trust_key",
            "valid": False,
            "key_id": key_id,
            "trusted_key_id": actual_key_id,
            "issuer": statement.get("issuer"),
            "statement": statement,
            "issues": ["attestation signing_key_id does not match trusted public key"],
        }

    try:
        key.verify(signature, canonical_bytes(statement))
    except InvalidSignature:
        return {
            "present": True,
            "status": "invalid_signature",
            "valid": False,
            "key_id": key_id,
            "trusted_key_id": actual_key_id,
            "issuer": statement.get("issuer"),
            "statement": statement,
            "issues": ["Ed25519 evidence attestation signature is invalid"],
        }

    return {
        "present": True,
        "status": "valid",
        "valid": True,
        "key_id": key_id,
        "trusted_key_id": actual_key_id,
        "issuer": statement.get("issuer"),
        "statement": statement,
        "issues": [],
    }
