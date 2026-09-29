#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = REPO_ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))

from app.evidence_attestation import verify_evidence_attestation


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Offline verifier for Be Safe Campaign Evidence Packs")
    parser.add_argument("pack")
    parser.add_argument("--public-key", default="")
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--campaign-id", default="")
    args = parser.parse_args()

    path = Path(args.pack)
    try:
        pack = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid evidence pack JSON: {exc}")

    manifest = pack.get("manifest") if isinstance(pack.get("manifest"), dict) else {}
    sections = pack.get("sections") if isinstance(pack.get("sections"), dict) else {}
    declared = pack.get("section_hashes") if isinstance(pack.get("section_hashes"), dict) else {}
    manifest_sections = manifest.get("section_hashes") if isinstance(manifest.get("section_hashes"), dict) else {}

    issues = []
    section_results = {}
    for name in sorted(set(sections) | set(declared) | set(manifest_sections)):
        computed = sha256(sections[name]) if name in sections else None
        ok = bool(
            name in sections
            and declared.get(name) == computed
            and manifest_sections.get(name) == computed
        )
        section_results[name] = ok
        if not ok:
            issues.append(f"section hash mismatch: {name}")

    content = {key: value for key, value in pack.items() if key != "manifest"}
    computed_pack = sha256(content)
    manifest_pack = str(manifest.get("pack_sha256") or "").lower()
    if computed_pack != manifest_pack:
        issues.append("pack SHA-256 does not match manifest")

    if args.expected_sha256 and computed_pack != args.expected_sha256.strip().lower():
        issues.append("pack SHA-256 does not match expected external anchor")

    if args.campaign_id and str(pack.get("campaign_id") or "") != args.campaign_id:
        issues.append("campaign_id does not match expected campaign")

    attestation = verify_evidence_attestation(
        manifest.get("attestation"),
        expected_pack_sha256=computed_pack,
        expected_campaign_id=args.campaign_id or str(pack.get("campaign_id") or ""),
        public_key_file=args.public_key or None,
    )
    if attestation.get("valid") is False:
        issues.extend(attestation.get("issues") or [])

    integrity_valid = not issues
    trust_established = bool(
        (args.expected_sha256 and computed_pack == args.expected_sha256.strip().lower())
        or attestation.get("valid") is True
    )
    result = {
        "valid": integrity_valid,
        "integrity_valid": integrity_valid,
        "trust_established": trust_established,
        "trust_status": (
            "invalid"
            if not integrity_valid
            else "signed_verified"
            if attestation.get("valid") is True
            else "external_anchor_verified"
            if args.expected_sha256 and computed_pack == args.expected_sha256.strip().lower()
            else "signed_unverified"
            if attestation.get("present")
            else "integrity_only"
        ),
        "pack_sha256": computed_pack,
        "manifest_pack_sha256": manifest_pack or None,
        "sections": section_results,
        "attestation": attestation,
        "issues": issues,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["valid"] else 2)


if __name__ == "__main__":
    main()
