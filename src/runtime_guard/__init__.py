"""
Frost Gate Spear - Runtime Behavior Guard Module

Implements v6.1 Blueprint requirements for runtime enforcement:
- Mode-aware behavior contract enforcement
- Autonomy level checks
- Human confirmation boundary enforcement
- Real rate limiting with persistent counters
- Dual attestation with witness hooks
- Allow/deny event emission with signatures

All runtime enforcement decisions are cryptographically attested.
"""

import base64
import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution modes with behavior contracts."""
    SIM = "SIM"
    LAB = "LAB"
    CANARY = "CANARY"
    SHADOW = "SHADOW"
    LIVE_GUARDED = "LIVE_GUARDED"
    LIVE_AUTONOMOUS = "LIVE_AUTONOMOUS"


class AutonomyLevel(Enum):
    """Autonomy levels for action execution."""
    NONE = 0  # All actions require human confirmation
    LOW = 1   # Read-only actions autonomous
    MEDIUM = 2  # Non-destructive actions autonomous
    HIGH = 3    # Most actions autonomous except destructive
    FULL = 4    # Fully autonomous (requires AO + special approval)


class Decision(Enum):
    """Guard decision types."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass
class BehaviorContract:
    """Defines behavior constraints for an execution mode."""
    mode: ExecutionMode
    max_autonomy_level: AutonomyLevel
    requires_human_confirmation_for_destructive: bool
    allows_scope_expansion: bool
    allows_live_targets: bool
    max_rate_per_target: int  # Actions per minute
    max_concurrent_actions: int
    requires_impact_preview: bool
    requires_dual_attestation: bool


# Mode-specific behavior contracts per v6.1
MODE_CONTRACTS: Dict[ExecutionMode, BehaviorContract] = {
    ExecutionMode.SIM: BehaviorContract(
        mode=ExecutionMode.SIM,
        max_autonomy_level=AutonomyLevel.FULL,
        requires_human_confirmation_for_destructive=False,
        allows_scope_expansion=False,
        allows_live_targets=False,
        max_rate_per_target=1000,
        max_concurrent_actions=100,
        requires_impact_preview=False,
        requires_dual_attestation=False,
    ),
    ExecutionMode.LAB: BehaviorContract(
        mode=ExecutionMode.LAB,
        max_autonomy_level=AutonomyLevel.HIGH,
        requires_human_confirmation_for_destructive=True,
        allows_scope_expansion=False,
        allows_live_targets=True,
        max_rate_per_target=60,
        max_concurrent_actions=10,
        requires_impact_preview=True,
        requires_dual_attestation=False,
    ),
    ExecutionMode.CANARY: BehaviorContract(
        mode=ExecutionMode.CANARY,
        max_autonomy_level=AutonomyLevel.MEDIUM,
        requires_human_confirmation_for_destructive=True,
        allows_scope_expansion=False,
        allows_live_targets=True,
        max_rate_per_target=30,
        max_concurrent_actions=5,
        requires_impact_preview=True,
        requires_dual_attestation=True,
    ),
    ExecutionMode.SHADOW: BehaviorContract(
        mode=ExecutionMode.SHADOW,
        max_autonomy_level=AutonomyLevel.LOW,
        requires_human_confirmation_for_destructive=True,
        allows_scope_expansion=False,
        allows_live_targets=True,
        max_rate_per_target=10,
        max_concurrent_actions=3,
        requires_impact_preview=True,
        requires_dual_attestation=True,
    ),
    ExecutionMode.LIVE_GUARDED: BehaviorContract(
        mode=ExecutionMode.LIVE_GUARDED,
        max_autonomy_level=AutonomyLevel.LOW,
        requires_human_confirmation_for_destructive=True,
        allows_scope_expansion=False,
        allows_live_targets=True,
        max_rate_per_target=5,
        max_concurrent_actions=2,
        requires_impact_preview=True,
        requires_dual_attestation=True,
    ),
    ExecutionMode.LIVE_AUTONOMOUS: BehaviorContract(
        mode=ExecutionMode.LIVE_AUTONOMOUS,
        max_autonomy_level=AutonomyLevel.HIGH,
        requires_human_confirmation_for_destructive=True,
        allows_scope_expansion=False,
        allows_live_targets=True,
        max_rate_per_target=10,
        max_concurrent_actions=5,
        requires_impact_preview=True,
        requires_dual_attestation=True,
    ),
}


@dataclass
class GuardDecision:
    """A runtime guard decision with attestation."""
    decision: Decision
    guard_id: str
    action_id: str
    timestamp: datetime
    rule: str
    reason: str
    attestation_signature: Optional[str] = None
    attestation_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DualAttestation:
    """Dual attestation from control plane and runtime guard."""
    attestation_id: str
    control_plane_attestation: Dict[str, Any]
    runtime_guard_attestation: Dict[str, Any]
    combined_hash: str
    witness_checkpoint: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RateLimitCounter:
    """
    Persistent rate limit counter using SQLite.

    Tracks action rates per target with sliding window.
    """

    def __init__(self, db_path: Optional[Path] = None, window_seconds: int = 60):
        """
        Initialize rate limit counter.

        Args:
            db_path: Path to SQLite database
            window_seconds: Sliding window size in seconds
        """
        if db_path is None:
            db_path = Path(__file__).parent.parent.parent / "data" / "rate_limits.db"

        self._db_path = db_path
        self._window_seconds = window_seconds
        self._lock = threading.RLock()

        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_target_time
                ON rate_events(target_id, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_campaign
                ON rate_events(campaign_id)
            """)
            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        return sqlite3.connect(
            str(self._db_path),
            timeout=30.0,
            check_same_thread=False,
        )

    def record_action(
        self,
        target_id: str,
        campaign_id: str,
        action_type: str = "default",
    ) -> None:
        """Record an action for rate limiting."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO rate_events (target_id, campaign_id, action_type, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (target_id, campaign_id, action_type, time.time())
                )
                conn.commit()

    def get_rate(self, target_id: str, window_seconds: Optional[int] = None) -> int:
        """
        Get the current action rate for a target.

        Args:
            target_id: Target to check
            window_seconds: Window size (uses default if not specified)

        Returns:
            Number of actions in the window
        """
        window = window_seconds or self._window_seconds
        cutoff = time.time() - window

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT COUNT(*) FROM rate_events
                    WHERE target_id = ? AND timestamp > ?
                    """,
                    (target_id, cutoff)
                )
                result = cursor.fetchone()
                return result[0] if result else 0

    def check_rate(
        self,
        target_id: str,
        max_rate: int,
        window_seconds: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """
        Check if action would exceed rate limit.

        Args:
            target_id: Target to check
            max_rate: Maximum allowed rate
            window_seconds: Window size

        Returns:
            Tuple of (allowed, current_rate)
        """
        current_rate = self.get_rate(target_id, window_seconds)
        return current_rate < max_rate, current_rate

    def cleanup_old_events(self, max_age_seconds: int = 3600) -> int:
        """
        Remove old rate events.

        Args:
            max_age_seconds: Maximum age of events to keep

        Returns:
            Number of events removed
        """
        cutoff = time.time() - max_age_seconds

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM rate_events WHERE timestamp < ?",
                    (cutoff,)
                )
                conn.commit()
                return cursor.rowcount


class RuntimeBehaviorGuard:
    """
    Runtime behavior guard enforcing mode-aware constraints.

    Implements v6.1 Blueprint requirements:
    - Mode-aware behavior contract enforcement
    - Autonomy level checks
    - Human confirmation boundary enforcement
    - Real rate limiting with persistent counters
    - Dual attestation with witness hooks
    """

    def __init__(
        self,
        guard_id: str,
        signing_key: Optional[Ed25519PrivateKey] = None,
        rate_counter: Optional[RateLimitCounter] = None,
        witness_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        """
        Initialize runtime behavior guard.

        Args:
            guard_id: Unique identifier for this guard instance
            signing_key: Ed25519 private key for signing attestations
            rate_counter: Rate limit counter (creates default if not provided)
            witness_callback: Optional callback for witness checkpoints
        """
        self._guard_id = guard_id
        self._signing_key = signing_key
        self._rate_counter = rate_counter or RateLimitCounter()
        self._witness_callback = witness_callback
        self._pending_confirmations: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    @property
    def guard_id(self) -> str:
        """Get guard ID."""
        return self._guard_id

    def get_contract(self, mode: ExecutionMode) -> BehaviorContract:
        """Get the behavior contract for a mode."""
        return MODE_CONTRACTS.get(mode, MODE_CONTRACTS[ExecutionMode.SIM])

    def enforce_action(
        self,
        action: Dict[str, Any],
        mode: ExecutionMode,
        autonomy_level: AutonomyLevel,
        campaign_id: str,
        human_confirmed: bool = False,
    ) -> GuardDecision:
        """
        Enforce behavior constraints on an action.

        Args:
            action: The action to validate
            mode: Current execution mode
            autonomy_level: Requested autonomy level
            campaign_id: Campaign identifier
            human_confirmed: Whether human confirmation was provided

        Returns:
            GuardDecision with allow/deny and reason
        """
        contract = self.get_contract(mode)
        action_id = action.get("action_id", str(uuid4()))
        target_id = action.get("target_id", "unknown")
        is_destructive = action.get("destructive", False)
        expands_scope = action.get("expands_scope", False)
        is_live_target = action.get("is_live_target", mode != ExecutionMode.SIM)

        # Check autonomy level
        if autonomy_level.value > contract.max_autonomy_level.value:
            return self._create_decision(
                Decision.DENY,
                action_id,
                "RUNTIME.AUTONOMY.EXCEEDED",
                f"Autonomy level {autonomy_level.name} exceeds max {contract.max_autonomy_level.name} for mode {mode.name}",
            )

        # Check scope expansion
        if expands_scope and not contract.allows_scope_expansion:
            return self._create_decision(
                Decision.DENY,
                action_id,
                "RUNTIME.SCOPE.EXPANSION_BLOCKED",
                f"Scope expansion not allowed in mode {mode.name}",
            )

        # Check live targets
        if is_live_target and not contract.allows_live_targets:
            return self._create_decision(
                Decision.DENY,
                action_id,
                "RUNTIME.TARGET.LIVE_BLOCKED",
                f"Live targets not allowed in mode {mode.name}",
            )

        # Check human confirmation for destructive actions
        if is_destructive and contract.requires_human_confirmation_for_destructive:
            if not human_confirmed:
                return self._create_decision(
                    Decision.REQUIRE_CONFIRMATION,
                    action_id,
                    "RUNTIME.CONFIRMATION.REQUIRED",
                    f"Human confirmation required for destructive action in mode {mode.name}",
                )

        # Check rate limit
        allowed, current_rate = self._rate_counter.check_rate(
            target_id,
            contract.max_rate_per_target,
        )
        if not allowed:
            return self._create_decision(
                Decision.DENY,
                action_id,
                "RUNTIME.RATE.EXCEEDED",
                f"Rate limit exceeded for target {target_id}: {current_rate}/{contract.max_rate_per_target} per minute",
                details={"current_rate": current_rate, "max_rate": contract.max_rate_per_target},
            )

        # Record action for rate limiting
        self._rate_counter.record_action(target_id, campaign_id, action.get("action_type", "default"))

        # All checks passed
        return self._create_decision(
            Decision.ALLOW,
            action_id,
            "RUNTIME.ALLOWED",
            f"Action allowed under mode {mode.name}",
        )

    def _create_decision(
        self,
        decision: Decision,
        action_id: str,
        rule: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        """Create a guard decision with attestation."""
        timestamp = datetime.now(timezone.utc)

        guard_decision = GuardDecision(
            decision=decision,
            guard_id=self._guard_id,
            action_id=action_id,
            timestamp=timestamp,
            rule=rule,
            reason=reason,
            details=details or {},
        )

        # Sign the decision if we have a signing key
        if self._signing_key:
            decision_data = {
                "decision": decision.value,
                "guard_id": self._guard_id,
                "action_id": action_id,
                "timestamp": timestamp.isoformat(),
                "rule": rule,
                "reason": reason,
            }
            message = json.dumps(decision_data, sort_keys=True).encode('utf-8')
            signature = self._signing_key.sign(message)
            guard_decision.attestation_signature = base64.b64encode(signature).decode('ascii')
            guard_decision.attestation_hash = hashlib.sha256(message).hexdigest()

        return guard_decision

    def create_dual_attestation(
        self,
        control_plane_attestation: Dict[str, Any],
        runtime_attestation: Dict[str, Any],
        request_witness: bool = True,
    ) -> DualAttestation:
        """
        Create a dual attestation combining control plane and runtime guard.

        Args:
            control_plane_attestation: Attestation from control plane
            runtime_attestation: Attestation from runtime guard
            request_witness: Whether to request witness checkpoint

        Returns:
            DualAttestation with combined hash
        """
        attestation_id = str(uuid4())
        timestamp = datetime.now(timezone.utc)

        # Compute combined hash
        combined_data = {
            "attestation_id": attestation_id,
            "control_plane": control_plane_attestation,
            "runtime_guard": runtime_attestation,
            "timestamp": timestamp.isoformat(),
        }
        combined_message = json.dumps(combined_data, sort_keys=True).encode('utf-8')
        combined_hash = hashlib.sha256(combined_message).hexdigest()

        # Request witness checkpoint if available
        witness_checkpoint = None
        if request_witness and self._witness_callback:
            try:
                witness_checkpoint = self._witness_callback({
                    "attestation_id": attestation_id,
                    "combined_hash": combined_hash,
                    "timestamp": timestamp.isoformat(),
                })
            except Exception as e:
                logger.warning(f"Witness callback failed: {e}")

        return DualAttestation(
            attestation_id=attestation_id,
            control_plane_attestation=control_plane_attestation,
            runtime_guard_attestation=runtime_attestation,
            combined_hash=combined_hash,
            witness_checkpoint=witness_checkpoint,
            timestamp=timestamp,
        )

    def check_permit_ttl(
        self,
        permit: Dict[str, Any],
    ) -> Tuple[bool, float]:
        """
        Check permit TTL and return remaining time.

        Args:
            permit: The execution permit

        Returns:
            Tuple of (expired, remaining_seconds)
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

    def register_human_confirmation(
        self,
        action_id: str,
        confirmer_id: str,
        confirmation_signature: Optional[str] = None,
    ) -> bool:
        """
        Register human confirmation for an action.

        Args:
            action_id: ID of the action being confirmed
            confirmer_id: ID of the person confirming
            confirmation_signature: Optional cryptographic signature

        Returns:
            True if confirmation was registered
        """
        with self._lock:
            self._pending_confirmations[action_id] = {
                "confirmer_id": confirmer_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": confirmation_signature,
            }
            return True

    def has_human_confirmation(self, action_id: str) -> bool:
        """Check if action has human confirmation."""
        with self._lock:
            return action_id in self._pending_confirmations

    def emit_event(
        self,
        event_type: str,
        action_id: str,
        decision: Decision,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an allow/deny event with optional signature.

        Args:
            event_type: Type of event (e.g., "ACTION_DECISION")
            action_id: ID of the action
            decision: The decision made
            details: Additional event details

        Returns:
            Event data including signature
        """
        timestamp = datetime.now(timezone.utc)

        event = {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "guard_id": self._guard_id,
            "action_id": action_id,
            "decision": decision.value,
            "timestamp": timestamp.isoformat(),
            "details": details or {},
        }

        # Sign the event
        if self._signing_key:
            message = json.dumps(event, sort_keys=True).encode('utf-8')
            signature = self._signing_key.sign(message)
            event["signature"] = {
                "algorithm": "Ed25519",
                "value": base64.b64encode(signature).decode('ascii'),
            }

        return event
