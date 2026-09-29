#!/usr/bin/env python3
import argparse
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = REPO_ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))

from app.evidence_attestation import public_key_id


def generate(args):
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)
    if private_path.exists() or public_path.exists():
        raise SystemExit("refusing to overwrite an existing evidence attestation key")

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

    print(f"private_key={private_path}")
    print(f"public_key={public_path}")
    print(f"key_id={public_key_id(key.public_key())}")


def show_id(args):
    path = Path(args.public_key)
    if not path.is_file():
        raise SystemExit(f"public key not found: {path}")
    key = load_pem_public_key(path.read_bytes())
    print(public_key_id(key))


def main():
    parser = argparse.ArgumentParser(description="Manage Be Safe Evidence Pack attestation keys")
    subs = parser.add_subparsers(dest="command", required=True)

    create = subs.add_parser("generate-key", help="generate a dedicated Ed25519 attestation keypair")
    create.add_argument("--private-key", required=True)
    create.add_argument("--public-key", required=True)
    create.set_defaults(func=generate)

    key_id = subs.add_parser("show-key-id", help="print SHA-256 key identifier for an Ed25519 public key")
    key_id.add_argument("--public-key", required=True)
    key_id.set_defaults(func=show_id)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
