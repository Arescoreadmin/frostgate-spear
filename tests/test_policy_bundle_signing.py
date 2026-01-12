"""
Tests for OPA Policy Bundle Signing (Gate M)

Validates v6.1 Blueprint Gate M requirements:
- OPA policy bundles MUST be signed
- Signatures MUST be verified before loading
- Unsigned bundles MUST be rejected
- Verification failure MUST block deployment

Tests:
- test_verification_passes_with_valid_bundle_and_sig
- test_verification_fails_if_bundle_modified
- test_verification_fails_if_sig_modified
- test_verification_fails_if_manifest_hash_mismatch
- test_engine_refuses_to_start_when_policy_verification_fails
"""

import base64
import hashlib
import json
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# PyNaCl for Ed25519 operations (more reliable than cryptography in test environments)
try:
    from nacl.signing import SigningKey, VerifyKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

# Fallback to cryptography
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


@pytest.fixture
def bundle_signing_keypair():
    """Generate Ed25519 keypair for bundle signing tests."""
    if NACL_AVAILABLE:
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        return {
            "private_bytes": bytes(signing_key),
            "public_bytes": bytes(verify_key),
            "private_b64": base64.b64encode(bytes(signing_key)).decode(),
            "public_b64": base64.b64encode(bytes(verify_key)).decode(),
            "sign": lambda msg: bytes(signing_key.sign(msg).signature),
            "verify": lambda msg, sig: verify_key.verify(msg, sig),
            "using": "nacl",
        }
    elif CRYPTOGRAPHY_AVAILABLE:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "private_bytes": private_bytes,
            "public_bytes": public_bytes,
            "private_b64": base64.b64encode(private_bytes).decode(),
            "public_b64": base64.b64encode(public_bytes).decode(),
            "sign": lambda msg: private_key.sign(msg),
            "verify": lambda msg, sig: public_key.verify(sig, msg),
            "using": "cryptography",
        }
    else:
        pytest.skip("Neither nacl nor cryptography available")


@pytest.fixture
def temp_bundle_dir(tmp_path):
    """Create temporary bundle directory with test policy files."""
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()

    # Create test policy files
    (policy_dir / "test_policy.rego").write_text(
        'package test\ndefault allow = false\n'
    )
    (policy_dir / "test_schema.json").write_text(
        '{"type": "object"}\n'
    )

    build_dir = tmp_path / "build"
    build_dir.mkdir()

    return {
        "policy_dir": policy_dir,
        "build_dir": build_dir,
        "root": tmp_path,
    }


@pytest.fixture
def create_signed_bundle(bundle_signing_keypair, temp_bundle_dir):
    """Factory fixture to create signed bundles."""

    def _create(
        tamper_bundle: bool = False,
        tamper_signature: bool = False,
        tamper_manifest_hash: bool = False,
        missing_bundle: bool = False,
        missing_sig: bool = False,
        missing_manifest: bool = False,
    ):
        policy_dir = temp_bundle_dir["policy_dir"]
        build_dir = temp_bundle_dir["build_dir"]

        # Create bundle tarball
        bundle_path = build_dir / "opa_bundle.tar.gz"
        if not missing_bundle:
            with tarfile.open(bundle_path, "w:gz") as tar:
                for f in policy_dir.iterdir():
                    tar.add(f, arcname=f.name)

            # Read bundle bytes
            with open(bundle_path, "rb") as f:
                bundle_bytes = f.read()

            # Compute hash of ORIGINAL bundle
            original_bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

            if tamper_bundle:
                # Tamper the bundle AFTER computing hash
                # This simulates an attacker modifying the bundle after signing
                tampered_bytes = bundle_bytes + b"tampered"
                with open(bundle_path, "wb") as f:
                    f.write(tampered_bytes)
                # Hash for signing is still original (simulates valid signature on original)
                bundle_hash = original_bundle_hash
            else:
                bundle_hash = original_bundle_hash
        else:
            bundle_bytes = b""
            bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

        if tamper_manifest_hash:
            # Use wrong hash in manifest
            manifest_hash = hashlib.sha256(b"wrong data").hexdigest()
        else:
            manifest_hash = bundle_hash

        # Sign the hash
        hash_bytes = bytes.fromhex(bundle_hash)
        signature = bundle_signing_keypair["sign"](hash_bytes)

        if tamper_signature:
            # Tamper the signature
            signature = b"invalid" * 8  # 64 bytes

        # Write signature file
        sig_path = build_dir / "opa_bundle.tar.gz.sig"
        if not missing_sig:
            with open(sig_path, "wb") as f:
                f.write(signature)

        # Create manifest
        manifest = {
            "manifest_version": "1.0.0",
            "bundle_hash": f"sha256:{manifest_hash}",
            "signature": {
                "algorithm": "Ed25519",
                "value": base64.b64encode(signature).decode(),
                "key_id": "test-bundle-signer",
                "signed_at": datetime.now(timezone.utc).isoformat(),
            },
            "build": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "policy_files": [
                    {"path": "test_policy.rego", "sha256": "abc123", "size": 100},
                    {"path": "test_schema.json", "sha256": "def456", "size": 50},
                ],
                "file_count": 2,
            },
        }

        manifest_path = build_dir / "opa_bundle.manifest.json"
        if not missing_manifest:
            with open(manifest_path, "w") as f:
                json.dump(manifest, f)

        return {
            "bundle_path": bundle_path,
            "sig_path": sig_path,
            "manifest_path": manifest_path,
            "bundle_hash": bundle_hash,
            "signature": signature,
            "manifest": manifest,
        }

    return _create


@pytest.fixture
def trust_store_file(bundle_signing_keypair, tmp_path):
    """Create trust store file with bundle signing key."""
    trust_store = {
        "version": "1.0.0",
        "trusted_keys": [
            {
                "key_id": "test-bundle-signer",
                "public_key": bundle_signing_keypair["public_b64"],
                "roles": ["bundle_signer"],
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2030-12-31T23:59:59Z",
                "revoked": False,
            }
        ],
    }

    trust_store_path = tmp_path / "trust_store.json"
    with open(trust_store_path, "w") as f:
        json.dump(trust_store, f)

    return trust_store_path


class TestBundleVerification:
    """Tests for OPA bundle signature verification."""

    def test_verification_passes_with_valid_bundle_and_sig(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification passes with valid bundle and signature."""
        from src.policy.bundle_verify import PolicyBundleVerifier

        bundle_info = create_signed_bundle()

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        result = verifier.verify_bundle(
            bundle_path=bundle_info["bundle_path"],
            sig_path=bundle_info["sig_path"],
            manifest_path=bundle_info["manifest_path"],
        )

        assert result.verified is True
        assert result.signature_valid is True
        assert result.key_id == "test-bundle-signer"
        assert result.bundle_hash.startswith("sha256:")

    def test_verification_fails_if_bundle_modified(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if bundle is tampered."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(tamper_bundle=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        assert exc_info.value.code == "BUNDLE.HASH.MISMATCH"
        assert "does not match" in exc_info.value.message.lower()

    def test_verification_fails_if_sig_modified(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if signature is tampered."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(tamper_signature=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        # Should fail on signature file mismatch or invalid signature
        assert exc_info.value.code in (
            "BUNDLE.SIGNATURE.FILE_MISMATCH",
            "BUNDLE.SIGNATURE.INVALID",
            "BUNDLE.SIGNATURE.ERROR",
        )

    def test_verification_fails_if_manifest_hash_mismatch(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if manifest hash doesn't match bundle."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(tamper_manifest_hash=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        assert exc_info.value.code == "BUNDLE.HASH.MISMATCH"

    def test_verification_fails_if_bundle_missing(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if bundle file is missing."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(missing_bundle=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        assert exc_info.value.code == "BUNDLE.FILE.NOT_FOUND"

    def test_verification_fails_if_sig_missing(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if signature file is missing."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(missing_sig=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        assert exc_info.value.code == "BUNDLE.SIGNATURE.NOT_FOUND"

    def test_verification_fails_if_manifest_missing(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that verification fails if manifest file is missing."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        bundle_info = create_signed_bundle(missing_manifest=True)

        verifier = PolicyBundleVerifier(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )
        verifier.load_trust_store()

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.verify_bundle(
                bundle_path=bundle_info["bundle_path"],
                sig_path=bundle_info["sig_path"],
                manifest_path=bundle_info["manifest_path"],
            )

        assert exc_info.value.code == "BUNDLE.MANIFEST.NOT_FOUND"


class TestTrustStoreLoading:
    """Tests for trust store loading."""

    def test_load_trust_store_success(self, trust_store_file):
        """Test successful trust store loading."""
        from src.policy.bundle_verify import PolicyBundleVerifier

        verifier = PolicyBundleVerifier(trust_store_path=trust_store_file)
        verifier.load_trust_store()

        assert len(verifier._trusted_keys) == 1
        assert "test-bundle-signer" in verifier._trusted_keys

    def test_load_trust_store_missing_file(self, tmp_path):
        """Test that missing trust store raises error."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        verifier = PolicyBundleVerifier(
            trust_store_path=tmp_path / "nonexistent.json"
        )

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.load_trust_store()

        assert exc_info.value.code == "BUNDLE.TRUST_STORE.NOT_FOUND"

    def test_load_trust_store_no_valid_keys(self, tmp_path):
        """Test that trust store with no bundle_signer keys raises error."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            PolicyBundleVerifier,
        )

        # Create trust store without bundle_signer role
        trust_store = {
            "trusted_keys": [
                {
                    "key_id": "other-key",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "roles": ["permit_signer"],  # Not bundle_signer
                }
            ]
        }
        trust_store_path = tmp_path / "trust_store.json"
        with open(trust_store_path, "w") as f:
            json.dump(trust_store, f)

        verifier = PolicyBundleVerifier(trust_store_path=trust_store_path)

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            verifier.load_trust_store()

        assert exc_info.value.code == "BUNDLE.TRUST_STORE.NO_VALID_KEYS"


class TestEngineIntegration:
    """Tests for ROE Engine integration with bundle verification."""

    @pytest.mark.asyncio
    async def test_engine_refuses_to_start_when_policy_verification_fails(
        self,
        tmp_path,
        bundle_signing_keypair,
    ):
        """
        Test that ROE Engine refuses to start when bundle verification fails.

        This is the critical fail-closed behavior test.
        """
        from src.core.config import Config, PolicyConfig
        from src.policy.bundle_verify import PolicyBundleVerificationError

        # Create config pointing to non-existent bundle
        config = Config()
        config.base_path = str(tmp_path)
        config.policy = PolicyConfig(
            bundle_verification_enabled=True,
            bundle_path="build/opa_bundle.tar.gz",
            trust_store_path="integrity/trust_store.json",
        )

        # Create trust store but no bundle
        integrity_dir = tmp_path / "integrity"
        integrity_dir.mkdir()
        trust_store = {
            "trusted_keys": [
                {
                    "key_id": "test-signer",
                    "public_key": bundle_signing_keypair["public_b64"],
                    "roles": ["bundle_signer"],
                }
            ]
        }
        with open(integrity_dir / "trust_store.json", "w") as f:
            json.dump(trust_store, f)

        # Engine should refuse to start
        from src.roe_engine import ROEEngine

        engine = ROEEngine(config)

        with pytest.raises(PolicyBundleVerificationError) as exc_info:
            await engine.start()

        assert exc_info.value.code == "BUNDLE.FILE.NOT_FOUND"

    @pytest.mark.asyncio
    async def test_engine_starts_when_verification_disabled(self, tmp_path):
        """Test that engine starts when bundle verification is disabled."""
        from src.core.config import Config, PolicyConfig

        config = Config()
        config.base_path = str(tmp_path)
        config.policy = PolicyConfig(
            bundle_verification_enabled=False,  # Disabled
        )

        from src.roe_engine import ROEEngine

        engine = ROEEngine(config)

        # Should not raise, but will fail on OPA connection (expected)
        try:
            await engine.start()
        except Exception:
            pass  # OPA connection failure is expected

        # Bundle verification was skipped
        assert engine._bundle_verified is False

    @pytest.mark.asyncio
    async def test_engine_starts_with_valid_bundle(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test that engine starts successfully with valid signed bundle."""
        from src.core.config import Config, PolicyConfig

        bundle_info = create_signed_bundle()
        root_path = temp_bundle_dir["root"]

        # Create config
        config = Config()
        config.base_path = str(root_path)
        config.policy = PolicyConfig(
            bundle_verification_enabled=True,
            bundle_path="build/opa_bundle.tar.gz",
            bundle_sig_path="build/opa_bundle.tar.gz.sig",
            bundle_manifest_path="build/opa_bundle.manifest.json",
            trust_store_path=str(trust_store_file.relative_to(root_path)),
        )

        # Move trust store to root
        import shutil
        integrity_dir = root_path / "integrity"
        integrity_dir.mkdir(exist_ok=True)
        shutil.copy(trust_store_file, integrity_dir / "trust_store.json")
        config.policy.trust_store_path = "integrity/trust_store.json"

        from src.roe_engine import ROEEngine

        engine = ROEEngine(config)

        # Start should succeed (OPA connection may fail, but verification passes)
        try:
            await engine.start()
        except Exception:
            pass  # OPA connection failure expected

        # Bundle should be verified
        assert engine._bundle_verified is True
        assert engine._bundle_verification_result is not None
        assert engine._bundle_verification_result.verified is True


class TestConvenienceFunction:
    """Tests for the verify_opa_bundle convenience function."""

    def test_verify_opa_bundle_success(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test convenience function with valid bundle."""
        from src.policy.bundle_verify import verify_opa_bundle

        bundle_info = create_signed_bundle()

        result = verify_opa_bundle(
            trust_store_path=trust_store_file,
            bundle_dir=temp_bundle_dir["build_dir"],
        )

        assert result.verified is True

    def test_verify_opa_bundle_failure(
        self,
        create_signed_bundle,
        trust_store_file,
        temp_bundle_dir,
    ):
        """Test convenience function with invalid bundle."""
        from src.policy.bundle_verify import (
            PolicyBundleVerificationError,
            verify_opa_bundle,
        )

        bundle_info = create_signed_bundle(tamper_bundle=True)

        with pytest.raises(PolicyBundleVerificationError):
            verify_opa_bundle(
                trust_store_path=trust_store_file,
                bundle_dir=temp_bundle_dir["build_dir"],
            )
