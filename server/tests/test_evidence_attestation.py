from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app import evidence_attestation


def write_keypair(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_path.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return private_path, public_path


def test_attestation_sign_and_verify(monkeypatch, tmp_path):
    private_path, public_path = write_keypair(tmp_path)
    monkeypatch.setenv("EVIDENCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PRIVATE_KEY_FILE", str(private_path))
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PUBLIC_KEY_FILE", str(public_path))
    monkeypatch.setenv("EVIDENCE_ATTESTATION_ISSUER", "Be Safe Test")

    attestation = evidence_attestation.build_evidence_attestation(
        pack_sha256="a" * 64,
        campaign_id="campaign-1",
        generated_at="2026-09-29T20:00:00+00:00",
    )
    result = evidence_attestation.verify_evidence_attestation(
        attestation,
        expected_pack_sha256="a" * 64,
        expected_campaign_id="campaign-1",
    )

    assert result["valid"] is True
    assert result["status"] == "valid"
    assert result["issuer"] == "Be Safe Test"
    assert len(result["key_id"]) == 64


def test_attestation_rejects_digest_tampering(monkeypatch, tmp_path):
    private_path, public_path = write_keypair(tmp_path)
    monkeypatch.setenv("EVIDENCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PRIVATE_KEY_FILE", str(private_path))
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PUBLIC_KEY_FILE", str(public_path))

    attestation = evidence_attestation.build_evidence_attestation(
        pack_sha256="a" * 64,
        campaign_id="campaign-1",
        generated_at="2026-09-29T20:00:00+00:00",
    )
    result = evidence_attestation.verify_evidence_attestation(
        attestation,
        expected_pack_sha256="b" * 64,
        expected_campaign_id="campaign-1",
    )

    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert "attestation pack SHA-256 does not match computed pack digest" in result["issues"]


def test_attestation_detects_signature_tampering(monkeypatch, tmp_path):
    private_path, public_path = write_keypair(tmp_path)
    monkeypatch.setenv("EVIDENCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PRIVATE_KEY_FILE", str(private_path))
    monkeypatch.setenv("EVIDENCE_ATTESTATION_PUBLIC_KEY_FILE", str(public_path))

    attestation = evidence_attestation.build_evidence_attestation(
        pack_sha256="a" * 64,
        campaign_id="campaign-1",
        generated_at="2026-09-29T20:00:00+00:00",
    )
    attestation["statement"]["issuer"] = "Altered issuer"
    result = evidence_attestation.verify_evidence_attestation(
        attestation,
        expected_pack_sha256="a" * 64,
        expected_campaign_id="campaign-1",
    )

    assert result["valid"] is False
    assert result["status"] == "invalid_signature"


def test_attestation_unsigned_when_disabled(monkeypatch):
    monkeypatch.delenv("EVIDENCE_ATTESTATION_ENABLED", raising=False)
    assert evidence_attestation.build_evidence_attestation(
        pack_sha256="a" * 64,
        campaign_id="campaign-1",
        generated_at="2026-09-29T20:00:00+00:00",
    ) is None
