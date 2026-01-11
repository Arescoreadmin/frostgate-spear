"""
Frost Gate Spear - Permit Enforcement Module

Implements v6.1 Blueprint requirements for execution permits:
- Cryptographic signature verification (Ed25519)
- Persistent nonce store (SQLite) for replay protection
- Per-action permit validation
- TTL enforcement with safe halt on expiry

All permit validation MUST happen:
1. At mission preflight/start
2. BEFORE EVERY action execution (per-action permit binding)
3. On any TTL expiry mid-run: halt safely
"""

import base64
import hashlib
import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class PermitValidationError(Exception):
    """Raised when permit validation fails."""

    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class PermitStatus(Enum):
    """Permit validation status."""
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    NONCE_REUSED = "NONCE_REUSED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    MODE_MISMATCH = "MODE_MISMATCH"
    REVOKED = "REVOKED"
    MALFORMED = "MALFORMED"


@dataclass
class PermitValidationResult:
    """Result of permit validation."""
    valid: bool
    status: PermitStatus
    permit_id: Optional[str] = None
    issues: List[Dict[str, Any]] = field(default_factory=list)
    expires_at: Optional[datetime] = None
    remaining_ttl_seconds: Optional[float] = None
    signature_verified: bool = False
    nonce_consumed: bool = False


@dataclass
class TrustedKey:
    """A trusted public key for signature verification."""
    key_id: str
    public_key: Ed25519PublicKey
    roles: Set[str]
    valid_from: datetime
    valid_to: Optional[datetime]
    revoked: bool = False


class TrustStoreVerifier:
    """
    Verifies signatures using trusted Ed25519 public keys.

    Loads keys from a trust store JSON file and validates
    signatures against registered keys.
    """

    def __init__(self, trust_store_path: Optional[Path] = None):
        """
        Initialize trust store verifier.

        Args:
            trust_store_path: Path to trust store JSON file.
                             If None, uses default location.
        """
        self._keys: Dict[str, TrustedKey] = {}
        self._lock = threading.RLock()

        if trust_store_path and trust_store_path.is_file():
            self._load_trust_store(trust_store_path)

    def _load_trust_store(self, path: Path) -> None:
        """Load trusted keys from trust store file."""
        try:
            with open(path, 'r') as f:
                store_data = json.load(f)

            for key_entry in store_data.get("trusted_keys", []):
                self._load_key_entry(key_entry)

            logger.info(f"Loaded {len(self._keys)} trusted keys from {path}")

        except Exception as e:
            logger.error(f"Failed to load trust store from {path}: {e}")

    def _load_key_entry(self, entry: Dict[str, Any]) -> None:
        """Load a single key entry into the store."""
        try:
            key_id = entry["key_id"]
            public_key_b64 = entry["public_key"]

            # Decode and load Ed25519 public key
            public_bytes = base64.b64decode(public_key_b64)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

            # Parse validity dates
            valid_from = datetime.fromisoformat(entry.get("valid_from", "2000-01-01T00:00:00Z").replace("Z", "+00:00"))
            valid_to_str = entry.get("valid_to")
            valid_to = datetime.fromisoformat(valid_to_str.replace("Z", "+00:00")) if valid_to_str else None

            self._keys[key_id] = TrustedKey(
                key_id=key_id,
                public_key=public_key,
                roles=set(entry.get("roles", [])),
                valid_from=valid_from,
                valid_to=valid_to,
                revoked=entry.get("revoked", False),
            )

        except Exception as e:
            logger.warning(f"Failed to load key entry {entry.get('key_id', 'unknown')}: {e}")

    def add_key(
        self,
        key_id: str,
        public_key: Ed25519PublicKey,
        roles: Optional[Set[str]] = None,
        valid_from: Optional[datetime] = None,
        valid_to: Optional[datetime] = None,
    ) -> None:
        """
        Add a trusted public key.

        Args:
            key_id: Unique identifier for the key
            public_key: Ed25519 public key
            roles: Set of roles this key can sign for
            valid_from: When key becomes valid
            valid_to: When key expires
        """
        with self._lock:
            self._keys[key_id] = TrustedKey(
                key_id=key_id,
                public_key=public_key,
                roles=roles or set(),
                valid_from=valid_from or datetime.now(timezone.utc),
                valid_to=valid_to,
                revoked=False,
            )

    def add_key_from_bytes(
        self,
        key_id: str,
        public_bytes: bytes,
        roles: Optional[Set[str]] = None,
    ) -> None:
        """Add a trusted public key from raw bytes."""
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        self.add_key(key_id, public_key, roles)

    def get_key(self, key_id: str) -> Optional[TrustedKey]:
        """Get a trusted key by ID."""
        with self._lock:
            return self._keys.get(key_id)

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a trusted key."""
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].revoked = True
                return True
            return False

    def verify_signature(
        self,
        message: bytes,
        signature: bytes,
        key_id: str,
        required_role: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signature using a trusted key.

        Args:
            message: The signed message
            signature: The signature bytes
            key_id: ID of the key to use for verification
            required_role: Optional role the key must have

        Returns:
            Tuple of (valid, error_message)
        """
        with self._lock:
            key = self._keys.get(key_id)

            if not key:
                return False, f"Unknown key ID: {key_id}"

            if key.revoked:
                return False, f"Key {key_id} has been revoked"

            now = datetime.now(timezone.utc)
            if now < key.valid_from:
                return False, f"Key {key_id} not yet valid"
            if key.valid_to and now > key.valid_to:
                return False, f"Key {key_id} has expired"

            if required_role and required_role not in key.roles:
                return False, f"Key {key_id} does not have role: {required_role}"

            try:
                key.public_key.verify(signature, message)
                return True, None
            except InvalidSignature:
                return False, "Invalid signature"
            except Exception as e:
                return False, f"Signature verification failed: {e}"


class PersistentNonceStore:
    """
    Persistent nonce store using SQLite.

    Ensures nonces cannot be reused across restarts and multi-instance
    deployments when using a shared database file.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize nonce store.

        Args:
            db_path: Path to SQLite database file.
                    If None, uses default location under data/.
        """
        if db_path is None:
            # Default to data/nonces.db relative to repo root
            db_path = Path(__file__).parent.parent.parent / "data" / "nonces.db"

        self._db_path = db_path
        self._lock = threading.RLock()

        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_nonces_campaign
                ON used_nonces(campaign_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_nonces_expires
                ON used_nonces(expires_at)
            """)
            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        return conn

    def consume_nonce(
        self,
        nonce: str,
        permit_id: str,
        campaign_id: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Consume a nonce, marking it as used.

        Args:
            nonce: The nonce to consume
            permit_id: ID of the permit containing this nonce
            campaign_id: ID of the campaign
            expires_at: Optional expiration time for the nonce record

        Returns:
            Tuple of (success, error_message)
            Returns False if nonce was already used
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Check if nonce already exists
                    cursor = conn.execute(
                        "SELECT permit_id, campaign_id, consumed_at FROM used_nonces WHERE nonce = ?",
                        (nonce,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        return False, (
                            f"Nonce already used by permit {existing['permit_id']} "
                            f"for campaign {existing['campaign_id']} at {existing['consumed_at']}"
                        )

                    # Insert new nonce
                    now = datetime.now(timezone.utc).isoformat()
                    expires_str = expires_at.isoformat() if expires_at else None

                    conn.execute(
                        """
                        INSERT INTO used_nonces (nonce, permit_id, campaign_id, consumed_at, expires_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (nonce, permit_id, campaign_id, now, expires_str)
                    )
                    conn.commit()

                    return True, None

            except sqlite3.IntegrityError:
                # Race condition: nonce was inserted by another process
                return False, "Nonce already used (concurrent insert)"
            except Exception as e:
                logger.error(f"Failed to consume nonce: {e}")
                return False, f"Database error: {e}"

    def is_nonce_used(self, nonce: str) -> bool:
        """Check if a nonce has been used."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM used_nonces WHERE nonce = ?",
                    (nonce,)
                )
                return cursor.fetchone() is not None

    def cleanup_expired(self) -> int:
        """
        Remove expired nonce records.

        Returns:
            Number of records removed
        """
        with self._lock:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                cursor = conn.execute(
                    "DELETE FROM used_nonces WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,)
                )
                conn.commit()
                return cursor.rowcount

    def get_nonces_for_campaign(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get all nonces used for a campaign."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM used_nonces WHERE campaign_id = ?",
                    (campaign_id,)
                )
                return [dict(row) for row in cursor.fetchall()]


class PermitValidator:
    """
    Validates execution permits with cryptographic verification.

    Implements v6.1 Blueprint requirements:
    - Signature verification using trust store
    - Nonce replay protection with persistent store
    - TTL enforcement
    - Per-action permit binding
    """

    def __init__(
        self,
        trust_store: Optional[TrustStoreVerifier] = None,
        nonce_store: Optional[PersistentNonceStore] = None,
        trust_store_path: Optional[Path] = None,
        nonce_db_path: Optional[Path] = None,
    ):
        """
        Initialize permit validator.

        Args:
            trust_store: Pre-configured trust store verifier
            nonce_store: Pre-configured nonce store
            trust_store_path: Path to trust store file (if trust_store not provided)
            nonce_db_path: Path to nonce database (if nonce_store not provided)
        """
        self._trust_store = trust_store or TrustStoreVerifier(trust_store_path)
        self._nonce_store = nonce_store or PersistentNonceStore(nonce_db_path)

    @property
    def trust_store(self) -> TrustStoreVerifier:
        """Get the trust store verifier."""
        return self._trust_store

    @property
    def nonce_store(self) -> PersistentNonceStore:
        """Get the nonce store."""
        return self._nonce_store

    def validate_permit(
        self,
        permit: Dict[str, Any],
        campaign: Optional[Dict[str, Any]] = None,
        action: Optional[Dict[str, Any]] = None,
        consume_nonce: bool = True,
    ) -> PermitValidationResult:
        """
        Validate an execution permit.

        Args:
            permit: The execution permit to validate
            campaign: Optional campaign to validate against
            action: Optional action to validate (for per-action checks)
            consume_nonce: Whether to consume the nonce (set False for dry-run)

        Returns:
            PermitValidationResult with validation status and issues
        """
        issues: List[Dict[str, Any]] = []
        permit_id = permit.get("permit_id")
        nonce_consumed = False
        signature_verified = False

        # Check required fields
        required_fields = ["permit_id", "campaign_id", "mode", "expires_at", "nonce", "sig"]
        for field in required_fields:
            if field not in permit:
                issues.append({
                    "code": "PERMIT.FIELD.MISSING",
                    "field": field,
                    "message": f"Required field '{field}' is missing",
                })

        if issues:
            return PermitValidationResult(
                valid=False,
                status=PermitStatus.MALFORMED,
                permit_id=permit_id,
                issues=issues,
            )

        # Parse expiration time
        try:
            expires_at_str = permit["expires_at"]
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            else:
                expires_at = expires_at_str
        except Exception as e:
            issues.append({
                "code": "PERMIT.EXPIRES_AT.INVALID",
                "message": f"Invalid expires_at format: {e}",
            })
            return PermitValidationResult(
                valid=False,
                status=PermitStatus.MALFORMED,
                permit_id=permit_id,
                issues=issues,
            )

        # Check expiration
        now = datetime.now(timezone.utc)
        if now >= expires_at:
            issues.append({
                "code": "PERMIT.EXPIRED",
                "expires_at": expires_at.isoformat(),
                "current_time": now.isoformat(),
                "message": "Permit has expired",
            })
            return PermitValidationResult(
                valid=False,
                status=PermitStatus.EXPIRED,
                permit_id=permit_id,
                issues=issues,
                expires_at=expires_at,
                remaining_ttl_seconds=0,
            )

        remaining_ttl = (expires_at - now).total_seconds()

        # Verify signature
        sig_info = permit.get("sig", {})
        sig_algorithm = sig_info.get("algorithm", "")
        sig_value = sig_info.get("value", "")
        key_id = sig_info.get("key_id", "")

        if sig_algorithm not in ("Ed25519", "EdDSA"):
            issues.append({
                "code": "PERMIT.SIGNATURE.UNSUPPORTED_ALGORITHM",
                "algorithm": sig_algorithm,
                "message": f"Unsupported signature algorithm: {sig_algorithm}. Only Ed25519 is supported.",
            })
        elif not sig_value or not key_id:
            issues.append({
                "code": "PERMIT.SIGNATURE.INCOMPLETE",
                "message": "Signature value or key_id is missing",
            })
        else:
            # Build message to verify (permit without signature)
            permit_for_signing = {k: v for k, v in permit.items() if k != "sig"}
            message = json.dumps(permit_for_signing, sort_keys=True, separators=(',', ':')).encode('utf-8')

            try:
                signature_bytes = base64.b64decode(sig_value)
                valid, error = self._trust_store.verify_signature(
                    message=message,
                    signature=signature_bytes,
                    key_id=key_id,
                    required_role="permit_signer",
                )

                if valid:
                    signature_verified = True
                else:
                    issues.append({
                        "code": "PERMIT.SIGNATURE.INVALID",
                        "key_id": key_id,
                        "error": error,
                        "message": f"Signature verification failed: {error}",
                    })

            except Exception as e:
                issues.append({
                    "code": "PERMIT.SIGNATURE.ERROR",
                    "message": f"Signature verification error: {e}",
                })

        if issues:
            return PermitValidationResult(
                valid=False,
                status=PermitStatus.SIGNATURE_INVALID,
                permit_id=permit_id,
                issues=issues,
                expires_at=expires_at,
                remaining_ttl_seconds=remaining_ttl,
                signature_verified=False,
            )

        # Check nonce
        nonce = permit["nonce"]
        campaign_id = permit["campaign_id"]

        if self._nonce_store.is_nonce_used(nonce):
            issues.append({
                "code": "PERMIT.NONCE.REUSED",
                "nonce": nonce,
                "message": "Nonce has already been used (replay attack prevented)",
            })
            return PermitValidationResult(
                valid=False,
                status=PermitStatus.NONCE_REUSED,
                permit_id=permit_id,
                issues=issues,
                expires_at=expires_at,
                remaining_ttl_seconds=remaining_ttl,
                signature_verified=signature_verified,
            )

        # Consume nonce if requested
        if consume_nonce:
            success, error = self._nonce_store.consume_nonce(
                nonce=nonce,
                permit_id=permit_id,
                campaign_id=campaign_id,
                expires_at=expires_at,
            )
            if not success:
                issues.append({
                    "code": "PERMIT.NONCE.CONSUMPTION_FAILED",
                    "error": error,
                    "message": f"Failed to consume nonce: {error}",
                })
                return PermitValidationResult(
                    valid=False,
                    status=PermitStatus.NONCE_REUSED,
                    permit_id=permit_id,
                    issues=issues,
                    expires_at=expires_at,
                    remaining_ttl_seconds=remaining_ttl,
                    signature_verified=signature_verified,
                )
            nonce_consumed = True

        # Campaign validation
        if campaign:
            campaign_id_permit = permit.get("campaign_id")
            campaign_id_actual = campaign.get("campaign_id")

            if campaign_id_permit != campaign_id_actual:
                issues.append({
                    "code": "PERMIT.CAMPAIGN_MISMATCH",
                    "permit_campaign": campaign_id_permit,
                    "actual_campaign": campaign_id_actual,
                    "message": "Permit campaign_id does not match campaign",
                })

            # Mode validation
            permit_mode = permit.get("mode", "")
            campaign_mode = campaign.get("mode", "")
            if permit_mode != campaign_mode:
                issues.append({
                    "code": "PERMIT.MODE_MISMATCH",
                    "permit_mode": permit_mode,
                    "campaign_mode": campaign_mode,
                    "message": "Permit mode does not match campaign mode",
                })

            if issues:
                return PermitValidationResult(
                    valid=False,
                    status=PermitStatus.SCOPE_MISMATCH,
                    permit_id=permit_id,
                    issues=issues,
                    expires_at=expires_at,
                    remaining_ttl_seconds=remaining_ttl,
                    signature_verified=signature_verified,
                    nonce_consumed=nonce_consumed,
                )

        # Action validation (per-action permit binding)
        if action:
            validation_issues = self._validate_action_against_permit(permit, action)
            issues.extend(validation_issues)

            if issues:
                return PermitValidationResult(
                    valid=False,
                    status=PermitStatus.SCOPE_MISMATCH,
                    permit_id=permit_id,
                    issues=issues,
                    expires_at=expires_at,
                    remaining_ttl_seconds=remaining_ttl,
                    signature_verified=signature_verified,
                    nonce_consumed=nonce_consumed,
                )

        return PermitValidationResult(
            valid=True,
            status=PermitStatus.VALID,
            permit_id=permit_id,
            issues=[],
            expires_at=expires_at,
            remaining_ttl_seconds=remaining_ttl,
            signature_verified=signature_verified,
            nonce_consumed=nonce_consumed,
        )

    def _validate_action_against_permit(
        self,
        permit: Dict[str, Any],
        action: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Validate an action against permit allowlists."""
        issues = []

        # Tool allowlist check
        tool_id = action.get("tool_id")
        if tool_id:
            tool_allowlist = permit.get("tool_allowlist", [])
            allowed_tools = {t.get("tool_id") for t in tool_allowlist}

            if tool_id not in allowed_tools:
                issues.append({
                    "code": "PERMIT.ACTION.TOOL_NOT_ALLOWED",
                    "tool_id": tool_id,
                    "allowed_tools": list(allowed_tools),
                    "message": f"Tool '{tool_id}' is not in permit allowlist",
                })

        # Target allowlist check
        target_id = action.get("target_id")
        if target_id:
            target_allowlist = permit.get("target_allowlist", [])
            allowed_targets = {t.get("target_id") for t in target_allowlist}

            if target_id not in allowed_targets:
                issues.append({
                    "code": "PERMIT.ACTION.TARGET_NOT_ALLOWED",
                    "target_id": target_id,
                    "allowed_targets": list(allowed_targets),
                    "message": f"Target '{target_id}' is not in permit allowlist",
                })

        # Entrypoint check
        entrypoint_id = action.get("entrypoint_id")
        if entrypoint_id:
            entrypoint_allowlist = permit.get("entrypoint_allowlist", [])
            allowed_entrypoints = {e.get("entrypoint_id") for e in entrypoint_allowlist}

            if entrypoint_id not in allowed_entrypoints:
                issues.append({
                    "code": "PERMIT.ACTION.ENTRYPOINT_NOT_ALLOWED",
                    "entrypoint_id": entrypoint_id,
                    "allowed_entrypoints": list(allowed_entrypoints),
                    "message": f"Entrypoint '{entrypoint_id}' is not in permit allowlist",
                })

        return issues

    def check_ttl_expiry(self, permit: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Check if permit TTL has expired.

        Args:
            permit: The execution permit

        Returns:
            Tuple of (expired, remaining_ttl_seconds)
        """
        try:
            expires_at_str = permit.get("expires_at", "")
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            else:
                expires_at = expires_at_str

            now = datetime.now(timezone.utc)
            remaining = (expires_at - now).total_seconds()

            return remaining <= 0, max(0, remaining)

        except Exception:
            return True, 0


def validate_signature(
    message: bytes,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> Tuple[bool, Optional[str]]:
    """
    Validate an Ed25519 signature.

    Args:
        message: The signed message
        signature: The signature bytes
        public_key: Ed25519 public key

    Returns:
        Tuple of (valid, error_message)
    """
    try:
        public_key.verify(signature, message)
        return True, None
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Signature verification failed: {e}"
