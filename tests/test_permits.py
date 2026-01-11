"""
Tests for the Permits Module

Validates v6.1 Blueprint requirements:
- Ed25519 signature verification
- Persistent SQLite nonce store
- Per-action permit validation
- TTL enforcement
"""

import base64
import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestTrustStoreVerifier:
    """Tests for TrustStoreVerifier."""

    def test_add_key_and_verify(self, sample_ed25519_keypair):
        """Test adding a key and verifying a signature."""
        from src.permits import TrustStoreVerifier

        store = TrustStoreVerifier()
        store.add_key(
            key_id="test-key-001",
            public_key=sample_ed25519_keypair["public_key"],
            roles={"permit_signer"},
        )

        # Create message and sign it
        message = b"test message"
        signature = sample_ed25519_keypair["private_key"].sign(message)

        # Verify
        valid, error = store.verify_signature(
            message=message,
            signature=signature,
            key_id="test-key-001",
        )

        assert valid is True
        assert error is None

    def test_verify_unknown_key_fails(self, sample_ed25519_keypair):
        """Test that unknown key IDs are rejected."""
        from src.permits import TrustStoreVerifier

        store = TrustStoreVerifier()

        message = b"test message"
        signature = sample_ed25519_keypair["private_key"].sign(message)

        valid, error = store.verify_signature(
            message=message,
            signature=signature,
            key_id="unknown-key",
        )

        assert valid is False
        assert "Unknown key ID" in error

    def test_revoked_key_fails(self, sample_ed25519_keypair):
        """Test that revoked keys are rejected."""
        from src.permits import TrustStoreVerifier

        store = TrustStoreVerifier()
        store.add_key(
            key_id="test-key-001",
            public_key=sample_ed25519_keypair["public_key"],
            roles={"permit_signer"},
        )
        store.revoke_key("test-key-001")

        message = b"test message"
        signature = sample_ed25519_keypair["private_key"].sign(message)

        valid, error = store.verify_signature(
            message=message,
            signature=signature,
            key_id="test-key-001",
        )

        assert valid is False
        assert "revoked" in error.lower()

    def test_invalid_signature_fails(self, sample_ed25519_keypair):
        """Test that invalid signatures are rejected."""
        from src.permits import TrustStoreVerifier

        store = TrustStoreVerifier()
        store.add_key(
            key_id="test-key-001",
            public_key=sample_ed25519_keypair["public_key"],
            roles={"permit_signer"},
        )

        message = b"test message"
        wrong_signature = b"invalid signature bytes" * 2  # Wrong signature

        valid, error = store.verify_signature(
            message=message,
            signature=wrong_signature,
            key_id="test-key-001",
        )

        assert valid is False


class TestPersistentNonceStore:
    """Tests for PersistentNonceStore."""

    def test_consume_nonce_success(self, temp_sqlite_db):
        """Test consuming a new nonce succeeds."""
        from src.permits import PersistentNonceStore

        store = PersistentNonceStore(db_path=temp_sqlite_db)

        success, error = store.consume_nonce(
            nonce="test-nonce-001",
            permit_id="permit-001",
            campaign_id="campaign-001",
        )

        assert success is True
        assert error is None

    def test_nonce_reuse_rejected(self, temp_sqlite_db):
        """Test that reusing a nonce is rejected."""
        from src.permits import PersistentNonceStore

        store = PersistentNonceStore(db_path=temp_sqlite_db)

        # Consume first time
        success1, _ = store.consume_nonce(
            nonce="test-nonce-001",
            permit_id="permit-001",
            campaign_id="campaign-001",
        )
        assert success1 is True

        # Try to reuse
        success2, error = store.consume_nonce(
            nonce="test-nonce-001",
            permit_id="permit-002",
            campaign_id="campaign-001",
        )

        assert success2 is False
        assert "already used" in error

    def test_nonce_persistence_across_instances(self, temp_sqlite_db):
        """Test that nonces persist across store instances."""
        from src.permits import PersistentNonceStore

        # First instance
        store1 = PersistentNonceStore(db_path=temp_sqlite_db)
        store1.consume_nonce("persistent-nonce", "p1", "c1")

        # Second instance (simulating restart)
        store2 = PersistentNonceStore(db_path=temp_sqlite_db)

        assert store2.is_nonce_used("persistent-nonce") is True

    def test_cleanup_expired_nonces(self, temp_sqlite_db):
        """Test cleanup of expired nonces."""
        from src.permits import PersistentNonceStore

        store = PersistentNonceStore(db_path=temp_sqlite_db)

        # Add nonce with past expiry
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        store.consume_nonce("expired-nonce", "p1", "c1", expires_at=past)

        # Add nonce with future expiry
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        store.consume_nonce("valid-nonce", "p2", "c1", expires_at=future)

        # Cleanup
        removed = store.cleanup_expired()

        assert removed == 1
        assert store.is_nonce_used("expired-nonce") is False
        assert store.is_nonce_used("valid-nonce") is True


class TestPermitValidator:
    """Tests for PermitValidator."""

    def test_valid_permit(self, valid_execution_permit, temp_sqlite_db):
        """Test validation of a valid permit."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore

        trust_store = TrustStoreVerifier()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=valid_execution_permit["keypair"]["public_key"],
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)

        validator = PermitValidator(
            trust_store=trust_store,
            nonce_store=nonce_store,
        )

        result = validator.validate_permit(valid_execution_permit["permit"])

        assert result.valid is True
        assert result.signature_verified is True
        assert result.nonce_consumed is True

    def test_expired_permit_rejected(self, valid_execution_permit, temp_sqlite_db):
        """Test that expired permits are rejected."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore, PermitStatus

        trust_store = TrustStoreVerifier()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=valid_execution_permit["keypair"]["public_key"],
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)
        validator = PermitValidator(trust_store=trust_store, nonce_store=nonce_store)

        # Modify permit to be expired
        permit = valid_execution_permit["permit"].copy()
        permit["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        result = validator.validate_permit(permit)

        assert result.valid is False
        assert result.status == PermitStatus.EXPIRED

    def test_invalid_signature_rejected(self, valid_execution_permit, temp_sqlite_db):
        """Test that permits with invalid signatures are rejected."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore, PermitStatus

        # Create trust store with DIFFERENT key
        trust_store = TrustStoreVerifier()
        different_key = Ed25519PrivateKey.generate().public_key()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=different_key,
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)
        validator = PermitValidator(trust_store=trust_store, nonce_store=nonce_store)

        result = validator.validate_permit(valid_execution_permit["permit"])

        assert result.valid is False
        assert result.status == PermitStatus.SIGNATURE_INVALID

    def test_nonce_reuse_rejected(self, valid_execution_permit, temp_sqlite_db):
        """Test that permits with reused nonces are rejected."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore, PermitStatus

        trust_store = TrustStoreVerifier()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=valid_execution_permit["keypair"]["public_key"],
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)
        validator = PermitValidator(trust_store=trust_store, nonce_store=nonce_store)

        # First validation - should succeed
        result1 = validator.validate_permit(valid_execution_permit["permit"])
        assert result1.valid is True

        # Second validation with same nonce - should fail
        result2 = validator.validate_permit(valid_execution_permit["permit"])
        assert result2.valid is False
        assert result2.status == PermitStatus.NONCE_REUSED

    def test_action_validation(self, valid_execution_permit, temp_sqlite_db):
        """Test per-action permit validation."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore

        trust_store = TrustStoreVerifier()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=valid_execution_permit["keypair"]["public_key"],
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)
        validator = PermitValidator(trust_store=trust_store, nonce_store=nonce_store)

        # Action matching permit allowlist
        valid_action = {
            "action_id": "action-001",
            "tool_id": "nmap",
            "target_id": "HOST-123456789",
            "entrypoint_id": "ep-001",
        }

        result = validator.validate_permit(
            valid_execution_permit["permit"],
            action=valid_action,
        )

        assert result.valid is True

    def test_action_tool_not_allowed(self, valid_execution_permit, temp_sqlite_db):
        """Test that actions with unauthorized tools are rejected."""
        from src.permits import PermitValidator, TrustStoreVerifier, PersistentNonceStore

        trust_store = TrustStoreVerifier()
        trust_store.add_key(
            key_id="test-key-001",
            public_key=valid_execution_permit["keypair"]["public_key"],
            roles={"permit_signer"},
        )

        nonce_store = PersistentNonceStore(db_path=temp_sqlite_db)
        validator = PermitValidator(trust_store=trust_store, nonce_store=nonce_store)

        # Action with unauthorized tool
        invalid_action = {
            "action_id": "action-001",
            "tool_id": "unauthorized-tool",  # Not in allowlist
            "target_id": "HOST-123456789",
        }

        result = validator.validate_permit(
            valid_execution_permit["permit"],
            action=invalid_action,
        )

        assert result.valid is False
        assert any("TOOL_NOT_ALLOWED" in issue["code"] for issue in result.issues)

    def test_ttl_check(self, valid_execution_permit):
        """Test TTL expiry checking."""
        from src.permits import PermitValidator

        validator = PermitValidator()

        # Valid permit
        expired, remaining = validator.check_ttl_expiry(valid_execution_permit["permit"])
        assert expired is False
        assert remaining > 0

        # Expired permit
        expired_permit = valid_execution_permit["permit"].copy()
        expired_permit["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        expired, remaining = validator.check_ttl_expiry(expired_permit)
        assert expired is True
        assert remaining == 0
