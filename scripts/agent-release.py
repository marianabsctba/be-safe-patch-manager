#!/usr/bin/env python3
import argparse
import json
import os
import re
import stat
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = REPO_ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))

from app.agent_updates import (
    MANIFEST_NAME,
    PRODUCT,
    SIGNATURE_NAME,
    canonical_manifest_bytes,
    load_signed_release,
    sha256_file,
)


def read_agent_metadata():
    text = (REPO_ROOT / "agent" / "patch_agent.py").read_text(encoding="utf-8")
    version_match = re.search(r'^AGENT_VERSION = "([^"]+)"$', text, re.MULTILINE)
    protocol_match = re.search(r"^AGENT_PROTOCOL = (\d+)$", text, re.MULTILINE)
    capabilities_match = re.search(
        r"^AGENT_CAPABILITIES = \((.*?)^\)$",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not version_match or not protocol_match or not capabilities_match:
        raise SystemExit("could not read agent version/protocol/capabilities")

    capabilities = re.findall(r'"([a-z0-9_]+)"', capabilities_match.group(1))
    return version_match.group(1), int(protocol_match.group(1)), capabilities


def generate_key(args):
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)
    if private_path.exists() or public_path.exists():
        raise SystemExit("refusing to overwrite an existing signing key")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)
    public_path.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    print(private_path)
    print(public_path)


def build(args):
    source_version, protocol, capabilities = read_agent_metadata()
    version = args.version or source_version
    if version != source_version:
        raise SystemExit(
            f"requested version {version} does not match AGENT_VERSION {source_version}"
        )

    private_path = Path(args.private_key)
    if not private_path.is_file():
        raise SystemExit(f"private key not found: {private_path}")

    try:
        key = load_pem_private_key(private_path.read_bytes(), password=None)
    except Exception as exc:
        raise SystemExit("invalid signing private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("signing private key must be Ed25519")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    artifact_name = f"be-safe-patch-agent-{version}.zip"
    artifact_path = output / artifact_name
    with zipfile.ZipFile(
        artifact_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        archive.write(REPO_ROOT / "agent" / "patch_agent.py", "patch_agent.py")
        archive.write(REPO_ROOT / "agent" / "requirements.txt", "requirements.txt")

    manifest = {
        "schema": 1,
        "product": PRODUCT,
        "version": version,
        "protocol": protocol,
        "capabilities": capabilities,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": {
            "filename": artifact_name,
            "sha256": sha256_file(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
        },
    }
    if args.source_commit:
        manifest["source_commit"] = args.source_commit

    manifest_path = output / MANIFEST_NAME
    signature_path = output / SIGNATURE_NAME
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    signature_path.write_bytes(key.sign(canonical_manifest_bytes(manifest)))

    print(manifest_path)
    print(signature_path)
    print(artifact_path)


def verify(args):
    result = load_signed_release(
        Path(args.release_dir),
        Path(args.public_key),
    )
    manifest = result["manifest"]
    print(
        json.dumps(
            {
                "ok": True,
                "version": manifest["version"],
                "protocol": manifest["protocol"],
                "artifact": manifest["artifact"]["filename"],
                "sha256": manifest["artifact"]["sha256"],
            },
            indent=2,
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Build and verify signed Be Safe agent releases")
    subs = parser.add_subparsers(dest="command", required=True)

    key = subs.add_parser("generate-key", help="generate an offline Ed25519 signing key")
    key.add_argument("--private-key", required=True)
    key.add_argument("--public-key", required=True)
    key.set_defaults(func=generate_key)

    builder = subs.add_parser("build", help="build and sign an agent release")
    builder.add_argument("--private-key", required=True)
    builder.add_argument("--output", required=True)
    builder.add_argument("--version", default="")
    builder.add_argument("--source-commit", default="")
    builder.set_defaults(func=build)

    verifier = subs.add_parser("verify", help="verify a signed agent release")
    verifier.add_argument("--public-key", required=True)
    verifier.add_argument("--release-dir", required=True)
    verifier.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
