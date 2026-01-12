"""
OPA Bundle Verification Module

Gate M implementation: Verifies OPA policy bundle signatures.
FAIL CLOSED: If verification fails, policy must NOT be loaded.

Verification steps:
1. Load trust store with bundle signer public keys
2. Verify bundle file exists
3. Verify signature file exists
4. Verify manifest file exists
5. Compute bundle hash and verify matches manifest
6. Verify signature over bundle hash using trust store

All failures result in PolicyBundleVerificationError.
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class PolicyBundleVerificationError(Exception):
    """
    Raised when bundle verification fails.

    This error MUST block policy loading - fail closed.
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


@dataclass
class BundleVerificationResult:
    """Result of bundle verification."""
    verified: bool
    bundle_hash: str
    manifest_hash: str
    signature_valid: bool
    key_id: str
    signed_at: Optional[str]
    policy_files: List[Dict[str, str]]
    issues: List[str]


class PolicyBundleVerifier:
    """
    Verifies OPA policy bundles using Ed25519 signatures.

    FAIL CLOSED: All verification failures raise PolicyBundleVerificationError.
    """

    REQUIRED_ROLE = "bundle_signer"

    def __init__(
        self,
        trust_store_path: Optional[Path] = None,
        bundle_dir: Optional[Path] = None,
    ):
        """
        Initialize bundle verifier.

        Args:
            trust_store_path: Path to trust store JSON file.
            bundle_dir: Directory containing bundle artifacts.
        """
        self._trust_store_path = trust_store_path
        self._bundle_dir = bundle_dir
        self._trusted_keys: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def load_trust_store(self, path: Optional[Path] = None) -> None:
        """
        Load trusted public keys from trust store.

        Args:
            path: Optional override for trust store path.

        Raises:
            PolicyBundleVerificationError: If trust store cannot be loaded.
        """
        store_path = path or self._trust_store_path

        if not store_path:
            raise PolicyBundleVerificationError(
                code="BUNDLE.TRUST_STORE.PATH_MISSING",
                message="Trust store path not configured",
            )

        if not store_path.is_file():
            raise PolicyBundleVerificationError(
                code="BUNDLE.TRUST_STORE.NOT_FOUND",
                message=f"Trust store not found: {store_path}",
            )

        try:
            with open(store_path, "r") as f:
                store_data = json.load(f)
        except json.JSONDecodeError as e:
            raise PolicyBundleVerificationError(
                code="BUNDLE.TRUST_STORE.INVALID_JSON",
                message=f"Trust store is not valid JSON: {e}",
            )
        except Exception as e:
            raise PolicyBundleVerificationError(
                code="BUNDLE.TRUST_STORE.READ_ERROR",
                message=f"Failed to read trust store: {e}",
            )

        # Load keys with bundle_signer role
        for key_entry in store_data.get("trusted_keys", []):
            try:
                key_id = key_entry.get("key_id")
                roles = set(key_entry.get("roles", []))

                if self.REQUIRED_ROLE not in roles:
                    continue  # Skip keys without bundle_signer role

                if key_entry.get("revoked", False):
                    logger.warning(f"Skipping revoked key: {key_id}")
                    continue

                # Check validity period
                valid_from = key_entry.get("valid_from")
                valid_to = key_entry.get("valid_to")
                now = datetime.now(timezone.utc)

                if valid_from:
                    from_dt = datetime.fromisoformat(
                        valid_from.replace("Z", "+00:00")
                    )
                    if now < from_dt:
                        logger.warning(f"Key {key_id} not yet valid")
                        continue

                if valid_to:
                    to_dt = datetime.fromisoformat(
                        valid_to.replace("Z", "+00:00")
                    )
                    if now > to_dt:
                        logger.warning(f"Key {key_id} has expired")
                        continue

                # Load public key
                public_key_b64 = key_entry.get("public_key")
                public_bytes = base64.b64decode(public_key_b64)
                public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

                self._trusted_keys[key_id] = {
                    "key_id": key_id,
                    "public_key": public_key,
                    "roles": roles,
                }

            except Exception as e:
                logger.warning(
                    f"Failed to load key entry {key_entry.get('key_id', 'unknown')}: {e}"
                )

        if not self._trusted_keys:
            raise PolicyBundleVerificationError(
                code="BUNDLE.TRUST_STORE.NO_VALID_KEYS",
                message="No valid bundle signing keys found in trust store",
            )

        self._loaded = True
        logger.info(
            f"Loaded {len(self._trusted_keys)} bundle signing keys from trust store"
        )

    def verify_bundle(
        self,
        bundle_path: Optional[Path] = None,
        sig_path: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
    ) -> BundleVerificationResult:
        """
        Verify OPA policy bundle signature and integrity.

        Args:
            bundle_path: Path to bundle tar.gz file.
            sig_path: Path to signature file.
            manifest_path: Path to manifest JSON file.

        Returns:
            BundleVerificationResult with verification details.

        Raises:
            PolicyBundleVerificationError: If verification fails (fail closed).
        """
        if not self._loaded:
            self.load_trust_store()

        # Resolve paths
        bundle_dir = self._bundle_dir or Path("build")
        bundle_file = bundle_path or (bundle_dir / "opa_bundle.tar.gz")
        sig_file = sig_path or (bundle_dir / "opa_bundle.tar.gz.sig")
        manifest_file = manifest_path or (bundle_dir / "opa_bundle.manifest.json")

        issues: List[str] = []

        # FAIL CLOSED: Check all required files exist
        if not bundle_file.is_file():
            raise PolicyBundleVerificationError(
                code="BUNDLE.FILE.NOT_FOUND",
                message=f"Bundle file not found: {bundle_file}",
                details={"path": str(bundle_file)},
            )

        if not sig_file.is_file():
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.NOT_FOUND",
                message=f"Signature file not found: {sig_file}",
                details={"path": str(sig_file)},
            )

        if not manifest_file.is_file():
            raise PolicyBundleVerificationError(
                code="BUNDLE.MANIFEST.NOT_FOUND",
                message=f"Manifest file not found: {manifest_file}",
                details={"path": str(manifest_file)},
            )

        # Load manifest
        try:
            with open(manifest_file, "r") as f:
                manifest = json.load(f)
        except json.JSONDecodeError as e:
            raise PolicyBundleVerificationError(
                code="BUNDLE.MANIFEST.INVALID_JSON",
                message=f"Manifest is not valid JSON: {e}",
            )

        # Extract manifest data
        manifest_bundle_hash = manifest.get("bundle_hash", "")
        if manifest_bundle_hash.startswith("sha256:"):
            manifest_bundle_hash = manifest_bundle_hash[7:]

        sig_info = manifest.get("signature", {})
        sig_algorithm = sig_info.get("algorithm", "")
        sig_value = sig_info.get("value", "")
        key_id = sig_info.get("key_id", "")
        signed_at = sig_info.get("signed_at")

        policy_files = manifest.get("build", {}).get("policy_files", [])

        # FAIL CLOSED: Verify signature algorithm
        if sig_algorithm not in ("Ed25519", "EdDSA"):
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.UNSUPPORTED_ALGORITHM",
                message=f"Unsupported signature algorithm: {sig_algorithm}. Only Ed25519 supported.",
                details={"algorithm": sig_algorithm},
            )

        # FAIL CLOSED: Check key is trusted
        if key_id not in self._trusted_keys:
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.UNKNOWN_KEY",
                message=f"Signature key not in trust store: {key_id}",
                details={"key_id": key_id},
            )

        # Compute actual bundle hash
        with open(bundle_file, "rb") as f:
            bundle_bytes = f.read()

        actual_bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

        # FAIL CLOSED: Verify hash matches manifest
        if actual_bundle_hash != manifest_bundle_hash:
            raise PolicyBundleVerificationError(
                code="BUNDLE.HASH.MISMATCH",
                message="Bundle hash does not match manifest",
                details={
                    "expected": manifest_bundle_hash,
                    "actual": actual_bundle_hash,
                },
            )

        # Read signature from file
        with open(sig_file, "rb") as f:
            sig_file_bytes = f.read()

        # Also verify signature in manifest matches file
        sig_manifest_bytes = base64.b64decode(sig_value)
        if sig_file_bytes != sig_manifest_bytes:
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.FILE_MISMATCH",
                message="Signature file does not match manifest signature",
            )

        # FAIL CLOSED: Verify signature
        trusted_key = self._trusted_keys[key_id]
        public_key: Ed25519PublicKey = trusted_key["public_key"]

        try:
            # Signature is over the hash bytes
            hash_bytes = bytes.fromhex(actual_bundle_hash)
            public_key.verify(sig_file_bytes, hash_bytes)
            signature_valid = True
        except InvalidSignature:
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.INVALID",
                message="Bundle signature verification failed",
                details={"key_id": key_id},
            )
        except Exception as e:
            raise PolicyBundleVerificationError(
                code="BUNDLE.SIGNATURE.ERROR",
                message=f"Signature verification error: {e}",
            )

        logger.info(
            f"Bundle verification successful: hash={actual_bundle_hash[:16]}..., "
            f"key={key_id}, signed_at={signed_at}"
        )

        return BundleVerificationResult(
            verified=True,
            bundle_hash=f"sha256:{actual_bundle_hash}",
            manifest_hash=f"sha256:{manifest_bundle_hash}",
            signature_valid=signature_valid,
            key_id=key_id,
            signed_at=signed_at,
            policy_files=policy_files,
            issues=issues,
        )


def verify_opa_bundle(
    trust_store_path: Path,
    bundle_dir: Optional[Path] = None,
    bundle_path: Optional[Path] = None,
    sig_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
) -> BundleVerificationResult:
    """
    Convenience function to verify an OPA bundle.

    Args:
        trust_store_path: Path to trust store JSON file.
        bundle_dir: Directory containing bundle artifacts.
        bundle_path: Optional explicit path to bundle file.
        sig_path: Optional explicit path to signature file.
        manifest_path: Optional explicit path to manifest file.

    Returns:
        BundleVerificationResult on success.

    Raises:
        PolicyBundleVerificationError: If verification fails.
    """
    verifier = PolicyBundleVerifier(
        trust_store_path=trust_store_path,
        bundle_dir=bundle_dir,
    )
    verifier.load_trust_store()
    return verifier.verify_bundle(
        bundle_path=bundle_path,
        sig_path=sig_path,
        manifest_path=manifest_path,
    )
