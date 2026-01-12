#!/usr/bin/env python3
"""
OPA Bundle Signing Script

Gate M implementation: Signs OPA policy bundles with Ed25519.
Creates:
- build/opa_bundle.tar.gz (the bundle)
- build/opa_bundle.tar.gz.sig (Ed25519 signature)
- build/opa_bundle.manifest.json (manifest with hashes)

Usage:
    python scripts/sign_opa_bundle.py --key-file <path> [--output-dir <path>]
    python scripts/sign_opa_bundle.py --key-b64 <base64_key> [--output-dir <path>]

For CI: Use environment variable OPA_SIGNING_KEY_B64 for the base64-encoded private key.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization


def discover_repo_root() -> Path:
    """Discover the repository root."""
    current = Path(__file__).resolve().parent
    for _ in range(10):
        if (current / "src").is_dir() and (current / "policy").is_dir():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise RuntimeError("Could not discover repo root")


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_bytes_hash(data: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def collect_policy_files(policy_dir: Path) -> List[Dict[str, str]]:
    """Collect all policy files and their hashes."""
    policy_files = []

    for ext in ["*.rego", "*.json"]:
        for file_path in sorted(policy_dir.glob(ext)):
            policy_files.append({
                "path": file_path.name,
                "sha256": compute_file_hash(file_path),
                "size": file_path.stat().st_size,
            })

    return policy_files


def create_bundle(policy_dir: Path, output_path: Path) -> Tuple[bytes, List[Dict[str, str]]]:
    """
    Create OPA bundle tar.gz file.

    Returns:
        Tuple of (bundle_bytes, policy_file_list)
    """
    policy_files = collect_policy_files(policy_dir)

    if not policy_files:
        raise RuntimeError(f"No policy files found in {policy_dir}")

    # Create tarball
    with tarfile.open(output_path, "w:gz") as tar:
        for file_info in policy_files:
            file_path = policy_dir / file_info["path"]
            tar.add(file_path, arcname=file_info["path"])

    # Read bundle bytes
    with open(output_path, "rb") as f:
        bundle_bytes = f.read()

    return bundle_bytes, policy_files


def load_private_key(key_file: Optional[Path], key_b64: Optional[str]) -> Ed25519PrivateKey:
    """Load Ed25519 private key from file or base64 string."""
    if key_b64:
        # Decode base64 private key
        key_bytes = base64.b64decode(key_b64)
        return Ed25519PrivateKey.from_private_bytes(key_bytes)

    if key_file:
        with open(key_file, "rb") as f:
            key_data = f.read()

        # Try raw bytes first (32 bytes)
        if len(key_data) == 32:
            return Ed25519PrivateKey.from_private_bytes(key_data)

        # Try base64-encoded raw bytes
        try:
            decoded = base64.b64decode(key_data.strip())
            if len(decoded) == 32:
                return Ed25519PrivateKey.from_private_bytes(decoded)
        except Exception:
            pass

        # Try PEM format
        return serialization.load_pem_private_key(key_data, password=None)

    # Try environment variable
    env_key = os.environ.get("OPA_SIGNING_KEY_B64")
    if env_key:
        key_bytes = base64.b64decode(env_key)
        return Ed25519PrivateKey.from_private_bytes(key_bytes)

    raise RuntimeError(
        "No signing key provided. Use --key-file, --key-b64, or OPA_SIGNING_KEY_B64 env var"
    )


def sign_bundle(private_key: Ed25519PrivateKey, bundle_hash: str) -> bytes:
    """Sign the bundle hash with Ed25519."""
    # Sign the hash bytes (not the hex string)
    hash_bytes = bytes.fromhex(bundle_hash)
    return private_key.sign(hash_bytes)


def create_manifest(
    bundle_hash: str,
    signature: bytes,
    policy_files: List[Dict[str, str]],
    key_id: str,
) -> Dict:
    """Create bundle manifest."""
    return {
        "manifest_version": "1.0.0",
        "bundle_hash": f"sha256:{bundle_hash}",
        "signature": {
            "algorithm": "Ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
            "key_id": key_id,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        },
        "build": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_files": policy_files,
            "file_count": len(policy_files),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Sign OPA policy bundle with Ed25519"
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        help="Path to Ed25519 private key file",
    )
    parser.add_argument(
        "--key-b64",
        type=str,
        help="Base64-encoded Ed25519 private key",
    )
    parser.add_argument(
        "--key-id",
        type=str,
        default="opa-bundle-signer-001",
        help="Key ID for the signature",
    )
    parser.add_argument(
        "--policy-dir",
        type=Path,
        help="Policy directory (default: <repo>/policy)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory (default: <repo>/build)",
    )

    args = parser.parse_args()

    # Discover paths
    repo_root = discover_repo_root()
    policy_dir = args.policy_dir or (repo_root / "policy")
    output_dir = args.output_dir or (repo_root / "build")

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Policy directory: {policy_dir}")
    print(f"Output directory: {output_dir}")

    # Load signing key
    print("Loading signing key...")
    try:
        private_key = load_private_key(args.key_file, args.key_b64)
    except Exception as e:
        print(f"ERROR: Failed to load signing key: {e}", file=sys.stderr)
        sys.exit(1)

    # Create bundle
    bundle_path = output_dir / "opa_bundle.tar.gz"
    print(f"Creating bundle: {bundle_path}")

    try:
        bundle_bytes, policy_files = create_bundle(policy_dir, bundle_path)
    except Exception as e:
        print(f"ERROR: Failed to create bundle: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  - Included {len(policy_files)} policy files")
    for pf in policy_files:
        print(f"    - {pf['path']} (sha256:{pf['sha256'][:16]}...)")

    # Compute bundle hash
    bundle_hash = compute_bytes_hash(bundle_bytes)
    print(f"  - Bundle hash: sha256:{bundle_hash[:32]}...")

    # Sign bundle
    print("Signing bundle...")
    signature = sign_bundle(private_key, bundle_hash)

    # Write signature file
    sig_path = output_dir / "opa_bundle.tar.gz.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
    print(f"  - Signature written to: {sig_path}")

    # Create and write manifest
    manifest = create_manifest(bundle_hash, signature, policy_files, args.key_id)
    manifest_path = output_dir / "opa_bundle.manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"  - Manifest written to: {manifest_path}")

    # Output public key for reference
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = base64.b64encode(public_bytes).decode("ascii")
    print(f"\nPublic key (base64): {public_b64}")
    print(f"Key ID: {args.key_id}")

    print("\nBundle signing complete!")
    print(f"  Bundle: {bundle_path}")
    print(f"  Signature: {sig_path}")
    print(f"  Manifest: {manifest_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
