"""
Witness Service - Blueprint v6.1 §3.1, §5.4, §10

Independent checkpoint witness signing for tamper evidence.
Provides cryptographic attestation separate from control plane.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend


class WitnessKeyType(Enum):
    """Witness key types per Blueprint v6.1 §5.3."""
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    ED25519 = "ED25519"


class CheckpointType(Enum):
    """Types of checkpoints that can be witnessed."""
    LEDGER_CHECKPOINT = "LEDGER_CHECKPOINT"
    EVIDENCE_ANCHOR = "EVIDENCE_ANCHOR"
    CAMPAIGN_MILESTONE = "CAMPAIGN_MILESTONE"
    DAILY_ANCHOR = "DAILY_ANCHOR"
    DOSSIER_SEAL = "DOSSIER_SEAL"


@dataclass
class WitnessKey:
    """Witness signing key (separate trust domain per Blueprint v6.1 §5.3)."""
    key_id: str
    key_type: WitnessKeyType
    public_key_pem: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False
    _private_key: Any = field(default=None, repr=False)


@dataclass
class WitnessCheckpoint:
    """A witnessed checkpoint with cryptographic attestation."""
    checkpoint_id: str
    checkpoint_type: CheckpointType
    tenant_id: str
    campaign_id: Optional[str]
    payload_hash: str
    previous_checkpoint_hash: Optional[str]
    sequence_number: int
    witnessed_at: datetime
    witness_id: str
    signature: str
    signature_algorithm: str
    merkle_root: Optional[str] = None
    anchor_proof: Optional[str] = None


@dataclass
class DualAttestation:
    """Dual attestation for allow/deny decisions per Blueprint v6.1 §5.4."""
    attestation_id: str
    decision: str  # ALLOW, DENY, ALLOW_WITH_CONDITIONS
    control_plane_attestation: dict
    runtime_guard_attestation: dict
    witness_signature: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WitnessService:
    """
    Independent checkpoint witness signing service.

    Per Blueprint v6.1 §3.1:
    - Provides independent checkpoint witness signing
    - Can be internalized or externalized
    - Signs ledger checkpoints and anchors

    Per Blueprint v6.1 §5.4:
    - Every allow/deny decision must be dual-attested
    - Witness-service periodically signs ledger checkpoints
    """

    def __init__(
        self,
        witness_id: str,
        key_rotation_hours: int = 24,
        checkpoint_interval_seconds: int = 300,
    ):
        self.witness_id = witness_id
        self.key_rotation_hours = key_rotation_hours
        self.checkpoint_interval_seconds = checkpoint_interval_seconds
        self._keys: dict[str, WitnessKey] = {}
        self._active_key_id: Optional[str] = None
        self._checkpoints: list[WitnessCheckpoint] = []
        self._sequence_counter: dict[str, int] = {}  # tenant_id -> sequence
        self._last_checkpoint_time: float = 0

    def generate_key(self, key_type: WitnessKeyType = WitnessKeyType.EC_P256) -> WitnessKey:
        """Generate a new witness signing key."""
        key_id = f"witness-key-{uuid4().hex[:12]}"

        if key_type == WitnessKeyType.EC_P256:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif key_type == WitnessKeyType.EC_P384:
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        now = datetime.now(timezone.utc)
        key = WitnessKey(
            key_id=key_id,
            key_type=key_type,
            public_key_pem=public_key_pem,
            created_at=now,
            expires_at=datetime.fromtimestamp(
                now.timestamp() + (self.key_rotation_hours * 3600),
                tz=timezone.utc
            ),
            _private_key=private_key
        )

        self._keys[key_id] = key
        self._active_key_id = key_id
        return key

    def get_active_key(self) -> Optional[WitnessKey]:
        """Get the current active signing key."""
        if not self._active_key_id:
            return None
        key = self._keys.get(self._active_key_id)
        if key and not key.revoked and key.expires_at > datetime.now(timezone.utc):
            return key
        return None

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a witness key."""
        if key_id in self._keys:
            self._keys[key_id].revoked = True
            if self._active_key_id == key_id:
                self._active_key_id = None
            return True
        return False

    def _sign_payload(self, payload: bytes, key: WitnessKey) -> str:
        """Sign a payload with the witness key."""
        if key.key_type in (WitnessKeyType.EC_P256, WitnessKeyType.EC_P384):
            signature = key._private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256())
            )
            return signature.hex()
        raise ValueError(f"Unsupported key type for signing: {key.key_type}")

    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash of data."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def create_checkpoint(
        self,
        checkpoint_type: CheckpointType,
        tenant_id: str,
        payload: dict,
        campaign_id: Optional[str] = None,
        merkle_root: Optional[str] = None,
    ) -> WitnessCheckpoint:
        """
        Create and sign a new checkpoint.

        Per Blueprint v6.1 §10:
        - Content-addressed immutable evidence bundles
        - Witness-service signs checkpoints and anchors
        """
        key = self.get_active_key()
        if not key:
            key = self.generate_key()

        # Get sequence number for tenant
        seq = self._sequence_counter.get(tenant_id, 0) + 1
        self._sequence_counter[tenant_id] = seq

        # Get previous checkpoint hash for chaining
        previous_hash = None
        tenant_checkpoints = [c for c in self._checkpoints if c.tenant_id == tenant_id]
        if tenant_checkpoints:
            previous_hash = self._compute_hash({
                'checkpoint_id': tenant_checkpoints[-1].checkpoint_id,
                'payload_hash': tenant_checkpoints[-1].payload_hash,
                'signature': tenant_checkpoints[-1].signature
            })

        payload_hash = self._compute_hash(payload)
        checkpoint_id = f"ckpt-{uuid4().hex[:16]}"
        witnessed_at = datetime.now(timezone.utc)

        # Create signing payload
        sign_payload = {
            'checkpoint_id': checkpoint_id,
            'checkpoint_type': checkpoint_type.value,
            'tenant_id': tenant_id,
            'campaign_id': campaign_id,
            'payload_hash': payload_hash,
            'previous_checkpoint_hash': previous_hash,
            'sequence_number': seq,
            'witnessed_at': witnessed_at.isoformat(),
            'witness_id': self.witness_id,
            'merkle_root': merkle_root
        }

        signature = self._sign_payload(
            json.dumps(sign_payload, sort_keys=True).encode('utf-8'),
            key
        )

        checkpoint = WitnessCheckpoint(
            checkpoint_id=checkpoint_id,
            checkpoint_type=checkpoint_type,
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            payload_hash=payload_hash,
            previous_checkpoint_hash=previous_hash,
            sequence_number=seq,
            witnessed_at=witnessed_at,
            witness_id=self.witness_id,
            signature=signature,
            signature_algorithm="ES256" if key.key_type == WitnessKeyType.EC_P256 else "ES384",
            merkle_root=merkle_root
        )

        self._checkpoints.append(checkpoint)
        self._last_checkpoint_time = time.time()

        return checkpoint

    def create_daily_anchor(self, tenant_id: str, ledger_state: dict) -> WitnessCheckpoint:
        """
        Create daily anchor checkpoint.

        Per Blueprint v6.1 §10:
        - Daily anchoring required
        - Missing anchors fail builds
        """
        return self.create_checkpoint(
            checkpoint_type=CheckpointType.DAILY_ANCHOR,
            tenant_id=tenant_id,
            payload={
                'anchor_type': 'DAILY',
                'anchor_date': datetime.now(timezone.utc).date().isoformat(),
                'ledger_state': ledger_state
            },
            merkle_root=ledger_state.get('merkle_root')
        )

    def create_dual_attestation(
        self,
        decision: str,
        control_plane_attestation: dict,
        runtime_guard_attestation: dict,
    ) -> DualAttestation:
        """
        Create dual attestation for allow/deny decision.

        Per Blueprint v6.1 §5.4:
        - Every allow/deny decision must be dual-attested
        - Control plane attests permit issuance and policy decision
        - Runtime behavior guard attests enforcement result
        """
        attestation_id = f"attest-{uuid4().hex[:16]}"

        # Witness the dual attestation
        key = self.get_active_key()
        if key:
            witness_payload = {
                'attestation_id': attestation_id,
                'decision': decision,
                'control_plane_hash': self._compute_hash(control_plane_attestation),
                'runtime_guard_hash': self._compute_hash(runtime_guard_attestation),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            witness_signature = self._sign_payload(
                json.dumps(witness_payload, sort_keys=True).encode('utf-8'),
                key
            )
        else:
            witness_signature = None

        return DualAttestation(
            attestation_id=attestation_id,
            decision=decision,
            control_plane_attestation=control_plane_attestation,
            runtime_guard_attestation=runtime_guard_attestation,
            witness_signature=witness_signature
        )

    def verify_checkpoint_chain(self, tenant_id: str) -> tuple[bool, list[str]]:
        """
        Verify the integrity of checkpoint chain for a tenant.

        Returns: (is_valid, list of issues)
        """
        issues = []
        tenant_checkpoints = sorted(
            [c for c in self._checkpoints if c.tenant_id == tenant_id],
            key=lambda c: c.sequence_number
        )

        if not tenant_checkpoints:
            return True, []

        # Verify sequence continuity
        for i, cp in enumerate(tenant_checkpoints):
            if cp.sequence_number != i + 1:
                issues.append(f"Sequence gap at checkpoint {cp.checkpoint_id}")

        # Verify chain links
        for i in range(1, len(tenant_checkpoints)):
            prev_cp = tenant_checkpoints[i - 1]
            curr_cp = tenant_checkpoints[i]

            expected_prev_hash = self._compute_hash({
                'checkpoint_id': prev_cp.checkpoint_id,
                'payload_hash': prev_cp.payload_hash,
                'signature': prev_cp.signature
            })

            if curr_cp.previous_checkpoint_hash != expected_prev_hash:
                issues.append(f"Chain break at checkpoint {curr_cp.checkpoint_id}")

        return len(issues) == 0, issues

    def get_checkpoints_for_campaign(self, campaign_id: str) -> list[WitnessCheckpoint]:
        """Get all checkpoints for a specific campaign."""
        return [c for c in self._checkpoints if c.campaign_id == campaign_id]

    def should_create_periodic_checkpoint(self) -> bool:
        """Check if a periodic checkpoint should be created."""
        return (time.time() - self._last_checkpoint_time) >= self.checkpoint_interval_seconds

    def export_witness_state(self) -> dict:
        """Export witness state for external verification."""
        return {
            'witness_id': self.witness_id,
            'active_key_id': self._active_key_id,
            'public_keys': {
                k.key_id: {
                    'key_type': k.key_type.value,
                    'public_key_pem': k.public_key_pem,
                    'created_at': k.created_at.isoformat(),
                    'expires_at': k.expires_at.isoformat(),
                    'revoked': k.revoked
                }
                for k in self._keys.values()
            },
            'checkpoint_count': len(self._checkpoints),
            'sequence_counters': self._sequence_counter.copy()
        }
