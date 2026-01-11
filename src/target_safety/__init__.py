"""
Frost Gate Spear - Target Safety Envelope Module

Implements v6.1 Blueprint requirements for target safety:
- Health probe gating before targeting
- Stop condition monitoring
- Impact prediction integration
- Target fingerprint validation
- Blast radius enforcement

All target interactions MUST pass safety envelope checks.
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import aiohttp

logger = logging.getLogger(__name__)


class TargetState(Enum):
    """Target health states."""
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNREACHABLE = "UNREACHABLE"
    FAILED = "FAILED"


class StopCondition(Enum):
    """Conditions that trigger execution stop."""
    TARGET_DEGRADED = "TARGET_DEGRADED"
    IMPACT_EXCEEDED = "IMPACT_EXCEEDED"
    FORENSIC_INCOMPLETE = "FORENSIC_INCOMPLETE"
    RATE_EXCEEDED = "RATE_EXCEEDED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TTL_EXPIRED = "TTL_EXPIRED"
    SCOPE_DRIFT = "SCOPE_DRIFT"
    MANUAL_HALT = "MANUAL_HALT"


@dataclass
class HealthProbeResult:
    """Result of a target health probe."""
    target_id: str
    state: TargetState
    timestamp: datetime
    latency_ms: Optional[float] = None
    fingerprint: Optional[str] = None
    fingerprint_match: bool = True
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SafetyEnvelope:
    """Safety envelope defining target constraints."""
    target_id: str
    blast_radius_cap: float  # 0-100 impact score
    max_actions: int
    expected_fingerprint: Optional[str] = None
    stop_conditions: Set[StopCondition] = field(default_factory=set)
    health_check_interval_seconds: int = 30
    impact_threshold_warning: float = 0.8  # 80% of cap triggers warning
    require_health_probe: bool = True


@dataclass
class TargetMetrics:
    """Real-time metrics for a target."""
    target_id: str
    current_impact: float = 0.0
    actions_executed: int = 0
    last_health_check: Optional[datetime] = None
    last_health_state: TargetState = TargetState.UNKNOWN
    cumulative_latency_ms: float = 0.0
    errors_encountered: int = 0


@dataclass
class SafetyCheckResult:
    """Result of a safety envelope check."""
    allowed: bool
    target_id: str
    stop_condition: Optional[StopCondition] = None
    reason: str = ""
    warnings: List[str] = field(default_factory=list)
    metrics: Optional[TargetMetrics] = None


class TargetSafetyEnforcer:
    """
    Enforces target safety envelopes.

    Implements v6.1 Blueprint requirements:
    - Health probe gating before targeting
    - Stop condition monitoring
    - Impact prediction enforcement
    - Fingerprint validation
    """

    def __init__(
        self,
        impact_predictor: Optional[Callable[[Dict[str, Any]], float]] = None,
        health_probe_timeout_seconds: float = 5.0,
    ):
        """
        Initialize target safety enforcer.

        Args:
            impact_predictor: Optional callback for impact prediction
            health_probe_timeout_seconds: Timeout for health probes
        """
        self._envelopes: Dict[str, SafetyEnvelope] = {}
        self._metrics: Dict[str, TargetMetrics] = {}
        self._impact_predictor = impact_predictor
        self._health_probe_timeout = health_probe_timeout_seconds
        self._stopped_targets: Set[str] = set()
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        """Start the safety enforcer."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._health_probe_timeout)
        )
        logger.info("Target safety enforcer started")

    async def stop(self) -> None:
        """Stop the safety enforcer."""
        if self._session:
            await self._session.close()
            self._session = None
        logger.info("Target safety enforcer stopped")

    def register_envelope(self, envelope: SafetyEnvelope) -> None:
        """
        Register a safety envelope for a target.

        Args:
            envelope: Safety envelope defining constraints
        """
        self._envelopes[envelope.target_id] = envelope
        self._metrics[envelope.target_id] = TargetMetrics(target_id=envelope.target_id)
        logger.info(f"Registered safety envelope for target {envelope.target_id}")

    def get_envelope(self, target_id: str) -> Optional[SafetyEnvelope]:
        """Get the safety envelope for a target."""
        return self._envelopes.get(target_id)

    def get_metrics(self, target_id: str) -> Optional[TargetMetrics]:
        """Get current metrics for a target."""
        return self._metrics.get(target_id)

    async def check_action_safety(
        self,
        target_id: str,
        action: Dict[str, Any],
        current_forensic_completeness: float = 1.0,
        current_budget_utilization: float = 0.0,
    ) -> SafetyCheckResult:
        """
        Check if an action is safe to execute against a target.

        Args:
            target_id: Target being acted upon
            action: Action to be executed
            current_forensic_completeness: Current forensic completeness (0-1)
            current_budget_utilization: Current budget utilization (0-1)

        Returns:
            SafetyCheckResult indicating if action is allowed
        """
        # Check if target is stopped
        if target_id in self._stopped_targets:
            return SafetyCheckResult(
                allowed=False,
                target_id=target_id,
                stop_condition=StopCondition.MANUAL_HALT,
                reason="Target has been stopped",
            )

        envelope = self._envelopes.get(target_id)
        if not envelope:
            # No envelope = no restrictions (but warn)
            logger.warning(f"No safety envelope for target {target_id}")
            return SafetyCheckResult(
                allowed=True,
                target_id=target_id,
                warnings=["No safety envelope registered for target"],
            )

        metrics = self._metrics.get(target_id, TargetMetrics(target_id=target_id))
        warnings = []

        # Check health probe requirement
        if envelope.require_health_probe:
            health_result = await self.probe_target_health(target_id)

            if health_result.state == TargetState.UNREACHABLE:
                return SafetyCheckResult(
                    allowed=False,
                    target_id=target_id,
                    stop_condition=StopCondition.TARGET_DEGRADED,
                    reason=f"Target unreachable: {health_result.error}",
                    metrics=metrics,
                )

            if health_result.state == TargetState.DEGRADED:
                if StopCondition.TARGET_DEGRADED in envelope.stop_conditions:
                    return SafetyCheckResult(
                        allowed=False,
                        target_id=target_id,
                        stop_condition=StopCondition.TARGET_DEGRADED,
                        reason="Target in degraded state",
                        metrics=metrics,
                    )
                warnings.append("Target is in degraded state")

            # Fingerprint validation
            if envelope.expected_fingerprint and not health_result.fingerprint_match:
                return SafetyCheckResult(
                    allowed=False,
                    target_id=target_id,
                    reason=f"Target fingerprint mismatch. Expected: {envelope.expected_fingerprint}, Got: {health_result.fingerprint}",
                    metrics=metrics,
                )

        # Check action count
        if metrics.actions_executed >= envelope.max_actions:
            return SafetyCheckResult(
                allowed=False,
                target_id=target_id,
                stop_condition=StopCondition.IMPACT_EXCEEDED,
                reason=f"Max actions reached: {metrics.actions_executed}/{envelope.max_actions}",
                metrics=metrics,
            )

        # Predict impact
        predicted_impact = self._predict_impact(action)
        projected_total = metrics.current_impact + predicted_impact

        if projected_total > envelope.blast_radius_cap:
            return SafetyCheckResult(
                allowed=False,
                target_id=target_id,
                stop_condition=StopCondition.IMPACT_EXCEEDED,
                reason=f"Projected impact {projected_total:.2f} exceeds cap {envelope.blast_radius_cap}",
                metrics=metrics,
            )

        if projected_total > envelope.blast_radius_cap * envelope.impact_threshold_warning:
            warnings.append(
                f"Approaching blast radius cap: {projected_total:.2f}/{envelope.blast_radius_cap}"
            )

        # Check forensic completeness
        if current_forensic_completeness < 0.95:
            if StopCondition.FORENSIC_INCOMPLETE in envelope.stop_conditions:
                return SafetyCheckResult(
                    allowed=False,
                    target_id=target_id,
                    stop_condition=StopCondition.FORENSIC_INCOMPLETE,
                    reason=f"Forensic completeness {current_forensic_completeness:.2%} below 95%",
                    metrics=metrics,
                )
            warnings.append(f"Forensic completeness at {current_forensic_completeness:.2%}")

        # Check budget
        if current_budget_utilization >= 1.0:
            return SafetyCheckResult(
                allowed=False,
                target_id=target_id,
                stop_condition=StopCondition.BUDGET_EXHAUSTED,
                reason="Budget exhausted",
                metrics=metrics,
            )

        if current_budget_utilization >= 0.9:
            warnings.append(f"Budget utilization at {current_budget_utilization:.0%}")

        return SafetyCheckResult(
            allowed=True,
            target_id=target_id,
            warnings=warnings,
            metrics=metrics,
        )

    async def probe_target_health(
        self,
        target_id: str,
        probe_url: Optional[str] = None,
    ) -> HealthProbeResult:
        """
        Probe target health status.

        Args:
            target_id: Target to probe
            probe_url: Optional URL to probe (for HTTP targets)

        Returns:
            HealthProbeResult with state and details
        """
        timestamp = datetime.now(timezone.utc)
        metrics = self._metrics.get(target_id)

        if not probe_url:
            # Simulated probe for non-HTTP targets
            return HealthProbeResult(
                target_id=target_id,
                state=TargetState.HEALTHY,
                timestamp=timestamp,
                fingerprint_match=True,
            )

        if not self._session:
            return HealthProbeResult(
                target_id=target_id,
                state=TargetState.UNKNOWN,
                timestamp=timestamp,
                error="Health probe session not initialized",
            )

        try:
            start_time = asyncio.get_event_loop().time()
            async with self._session.get(probe_url) as response:
                end_time = asyncio.get_event_loop().time()
                latency_ms = (end_time - start_time) * 1000

                # Compute fingerprint from response headers
                fingerprint = self._compute_fingerprint(dict(response.headers))

                # Check expected fingerprint
                envelope = self._envelopes.get(target_id)
                fingerprint_match = True
                if envelope and envelope.expected_fingerprint:
                    fingerprint_match = fingerprint == envelope.expected_fingerprint

                if response.status >= 500:
                    state = TargetState.FAILED
                elif response.status >= 400:
                    state = TargetState.DEGRADED
                else:
                    state = TargetState.HEALTHY

                result = HealthProbeResult(
                    target_id=target_id,
                    state=state,
                    timestamp=timestamp,
                    latency_ms=latency_ms,
                    fingerprint=fingerprint,
                    fingerprint_match=fingerprint_match,
                    details={"status_code": response.status},
                )

                # Update metrics
                if metrics:
                    metrics.last_health_check = timestamp
                    metrics.last_health_state = state
                    metrics.cumulative_latency_ms += latency_ms

                return result

        except asyncio.TimeoutError:
            if metrics:
                metrics.errors_encountered += 1
            return HealthProbeResult(
                target_id=target_id,
                state=TargetState.UNREACHABLE,
                timestamp=timestamp,
                error="Health probe timed out",
            )
        except Exception as e:
            if metrics:
                metrics.errors_encountered += 1
            return HealthProbeResult(
                target_id=target_id,
                state=TargetState.UNREACHABLE,
                timestamp=timestamp,
                error=str(e),
            )

    def record_action(
        self,
        target_id: str,
        action_id: str,
        impact_score: float,
    ) -> None:
        """
        Record an executed action for metrics tracking.

        Args:
            target_id: Target the action was executed against
            action_id: Unique action identifier
            impact_score: Impact score of the action
        """
        metrics = self._metrics.get(target_id)
        if metrics:
            metrics.actions_executed += 1
            metrics.current_impact += impact_score

    def stop_target(self, target_id: str, reason: str = "Manual stop") -> None:
        """
        Stop all actions against a target.

        Args:
            target_id: Target to stop
            reason: Reason for stopping
        """
        self._stopped_targets.add(target_id)
        logger.warning(f"Target {target_id} stopped: {reason}")

    def resume_target(self, target_id: str) -> bool:
        """
        Resume actions against a stopped target.

        Args:
            target_id: Target to resume

        Returns:
            True if target was resumed
        """
        if target_id in self._stopped_targets:
            self._stopped_targets.remove(target_id)
            logger.info(f"Target {target_id} resumed")
            return True
        return False

    def _predict_impact(self, action: Dict[str, Any]) -> float:
        """Predict impact of an action."""
        if self._impact_predictor:
            try:
                return self._impact_predictor(action)
            except Exception as e:
                logger.warning(f"Impact prediction failed: {e}")

        # Default impact estimation based on action type
        action_type = action.get("action_type", "")
        default_impacts = {
            "scan": 1.0,
            "enumerate": 2.0,
            "exploit": 10.0,
            "credential_access": 15.0,
            "lateral_movement": 20.0,
            "exfiltration": 25.0,
            "destructive": 50.0,
        }
        return default_impacts.get(action_type, 5.0)

    def _compute_fingerprint(self, headers: Dict[str, str]) -> str:
        """Compute fingerprint from response headers."""
        fingerprint_fields = ["Server", "X-Powered-By", "Content-Type"]
        fingerprint_data = "|".join(
            f"{k}={headers.get(k, '')}" for k in fingerprint_fields
        )
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

    def check_stop_conditions(
        self,
        target_id: str,
        forensic_completeness: float,
        budget_utilization: float,
        scope_drift_detected: bool,
        ttl_remaining_seconds: float,
    ) -> Optional[StopCondition]:
        """
        Check all stop conditions for a target.

        Args:
            target_id: Target to check
            forensic_completeness: Current forensic completeness
            budget_utilization: Current budget utilization
            scope_drift_detected: Whether scope drift was detected
            ttl_remaining_seconds: Remaining TTL in seconds

        Returns:
            StopCondition if one is triggered, None otherwise
        """
        envelope = self._envelopes.get(target_id)
        if not envelope:
            return None

        metrics = self._metrics.get(target_id)
        stop_conditions = envelope.stop_conditions

        # Check each condition
        if StopCondition.IMPACT_EXCEEDED in stop_conditions:
            if metrics and metrics.current_impact >= envelope.blast_radius_cap:
                return StopCondition.IMPACT_EXCEEDED

        if StopCondition.FORENSIC_INCOMPLETE in stop_conditions:
            if forensic_completeness < 0.95:
                return StopCondition.FORENSIC_INCOMPLETE

        if StopCondition.BUDGET_EXHAUSTED in stop_conditions:
            if budget_utilization >= 1.0:
                return StopCondition.BUDGET_EXHAUSTED

        if StopCondition.SCOPE_DRIFT in stop_conditions:
            if scope_drift_detected:
                return StopCondition.SCOPE_DRIFT

        if StopCondition.TTL_EXPIRED in stop_conditions:
            if ttl_remaining_seconds <= 0:
                return StopCondition.TTL_EXPIRED

        if StopCondition.TARGET_DEGRADED in stop_conditions:
            if metrics and metrics.last_health_state in [TargetState.DEGRADED, TargetState.FAILED]:
                return StopCondition.TARGET_DEGRADED

        return None
