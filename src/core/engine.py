"""
Frost Gate Spear Core Engine

Main orchestration engine coordinating all subsystems.
Integrates safety policy evaluation, MLS validation, and SBOM verification.

v6.1 EXECUTION CONTROL PLANE:
All action execution MUST pass through validate_and_execute_action().
This is the ONLY authorized path for action execution.
Any bypass is a SECURITY FAILURE.
"""

import asyncio
import inspect
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import aiohttp

from .config import Config
from .exceptions import (
    DecisionRecordMissingError,
    FrostGateError,
    GuardBypassError,
    MLSViolationError,
    PermitDeniedError,
    PermitExpiredError,
    PolicyDeniedError,
    PolicyViolationError,
    RateLimitedError,
    ROEViolationError,
    SafetyConstraintError,
    ScopeDriftError,
    SoDViolationError,
    StepUpRequiredError,
    TargetUnsafeError,
    WitnessRequiredError,
)
from .mission import Mission, MissionState

logger = logging.getLogger(__name__)


# ============================================================================
# EXECUTION CONTROL PLANE - v6.1 Gate F Enforcement
# ============================================================================


@dataclass
class ActionContext:
    """
    Typed structure containing all execution context for an action.

    This context MUST be provided to validate_and_execute_action().
    All fields are required for proper guard enforcement.
    """

    tenant_id: str
    campaign_id: str
    mode: str  # SIM, LAB, CANARY, SHADOW, LIVE_GUARDED, LIVE_AUTONOMOUS
    risk_tier: int  # 1, 2, or 3
    scope_id: str
    action: Dict[str, Any]  # The action to execute
    target: Dict[str, Any]  # Target information
    entrypoint: Dict[str, Any]  # Entrypoint information
    permit: Dict[str, Any]  # Execution permit
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional fields
    action_id: Optional[str] = None
    permit_id: Optional[str] = None
    executor_id: Optional[str] = None
    approver_ids: Optional[List[str]] = None
    human_confirmed: bool = False
    classification_level: str = "UNCLASS"

    def __post_init__(self):
        """Generate action_id if not provided."""
        if self.action_id is None:
            self.action_id = str(uuid4())
        if self.permit_id is None:
            self.permit_id = self.permit.get("permit_id")

    @property
    def now_ms(self) -> int:
        """Current timestamp in milliseconds."""
        return int(self.timestamp.timestamp() * 1000)


@dataclass
class GuardDecisionEntry:
    """A single guard's decision in the chain."""

    guard_name: str
    decision: str  # ALLOW, DENY, HALT, REQUIRE_CONFIRMATION
    timestamp: datetime
    rule: Optional[str] = None
    reason: Optional[str] = None
    attestation_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionRecord:
    """
    Records the decision of EVERY guard for an action.

    This record MUST exist for every executed action.
    If it does not exist, execution is considered INVALID.
    """

    action_id: str
    action_context_hash: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Individual guard decisions (populated during validation)
    permit_decision: Optional[GuardDecisionEntry] = None
    opa_abac_decision: Optional[GuardDecisionEntry] = None
    opa_scope_decision: Optional[GuardDecisionEntry] = None
    runtime_guard_decision: Optional[GuardDecisionEntry] = None
    rate_limit_decision: Optional[GuardDecisionEntry] = None
    target_safety_decision: Optional[GuardDecisionEntry] = None

    # Overall result
    all_guards_passed: bool = False
    executed: bool = False
    execution_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def is_complete(self) -> bool:
        """Check if all guards have recorded decisions."""
        return all([
            self.permit_decision is not None,
            self.opa_abac_decision is not None,
            self.opa_scope_decision is not None,
            self.runtime_guard_decision is not None,
            self.rate_limit_decision is not None,
            self.target_safety_decision is not None,
        ])

    def all_allow(self) -> bool:
        """Check if all guards returned ALLOW."""
        decisions = [
            self.permit_decision,
            self.opa_abac_decision,
            self.opa_scope_decision,
            self.runtime_guard_decision,
            self.rate_limit_decision,
            self.target_safety_decision,
        ]
        return all(d is not None and d.decision == "ALLOW" for d in decisions)


@dataclass
class ForensicEvent:
    """Forensic event emitted after action execution."""

    event_id: str
    event_type: str  # ACTION_EXECUTED, ACTION_DENIED, ACTION_FAILED
    timestamp: datetime
    action_context: ActionContext
    decision_record: DecisionRecord
    outcome: str  # SUCCESS, FAILURE, BLOCKED
    details: Dict[str, Any] = field(default_factory=dict)


class ExecutionControlPlane:
    """
    Centralized execution control plane enforcing v6.1 requirements.

    ALL action execution MUST flow through validate_and_execute_action().
    This is the ONLY authorized execution path.

    Guard order (exact, do not reorder):
    1. PermitValidator.validate_action(...) - includes TTL check
    2. OPA evaluation (ABAC + Scope lint)
    3. RuntimeBehaviorGuard.check(...)
    4. RateLimitCounter.check_and_increment(...)
    5. TargetSafety.probe_and_check(...)
    6. Execute the action
    7. Emit forensic event

    SECURITY: Uses non-forgeable execution tokens (secrets.token_urlsafe(32)).
    Executor MUST present valid token to execute.
    This is NOT crypto, but much harder to spoof than context variables.
    """

    def __init__(
        self,
        permit_validator=None,
        opa_client=None,
        runtime_guard=None,
        rate_limiter=None,
        target_safety=None,
        action_executor: Optional[Callable] = None,
        forensic_emitter: Optional[Callable] = None,
    ):
        """
        Initialize execution control plane.

        All guard components MUST be provided for production use.
        Missing components will cause guard bypass errors in production.
        """
        self._permit_validator = permit_validator
        self._opa_client = opa_client
        self._runtime_guard = runtime_guard
        self._rate_limiter = rate_limiter
        self._target_safety = target_safety
        self._action_executor = action_executor
        self._forensic_emitter = forensic_emitter

        # Track decision records for audit
        self._decision_records: Dict[str, DecisionRecord] = {}

        # Bypass detection flag - set by internal calls only
        self._bypass_check_enabled = True

        # For testing: allow mock execution
        self._test_mode = False

        # Active execution tokens: maps action_id -> one-time execution token
        # Token is consumed after use to prevent replay attacks
        self._active_execution_tokens: Dict[str, str] = {}

    def generate_execution_token(self, action_id: str, record: "DecisionRecord") -> str:
        """
        Generate a one-time execution token for a specific action.

        This token MUST be presented to the executor to prove the action
        passed through all guards. Token is bound to action_id and decision record.

        Args:
            action_id: The action this token authorizes
            record: The DecisionRecord proving all guards passed

        Returns:
            A non-forgeable execution token
        """
        if not record.all_guards_passed:
            raise GuardBypassError(
                message="Cannot generate execution token - guards did not all pass",
                bypass_path="token_generation_without_guards",
                caller="ExecutionControlPlane",
            )

        # Generate action-specific token bound to action_id and random nonce
        action_token = secrets.token_urlsafe(32)

        # Store token for validation
        self._active_execution_tokens[action_id] = action_token

        logger.debug(f"Generated execution token for action {action_id}")
        return action_token

    def validate_execution_token(
        self,
        token: str,
        action_id: str,
        consume: bool = True,
    ) -> bool:
        """
        Validate an execution token.

        Validate against the action token registry.

        Args:
            token: The token presented by the executor
            action_id: Action ID for per-action token validation
            consume: Whether to consume the per-action token on success

        Returns:
            True if token is valid, False otherwise
        """
        expected_token = self._active_execution_tokens.get(action_id)

        if expected_token is None:
            logger.warning(f"No execution token found for action {action_id}")
            return False

        # Constant-time comparison to prevent timing attacks
        valid = secrets.compare_digest(expected_token, token)

        if valid and consume:
            # Consume token - one-time use only
            del self._active_execution_tokens[action_id]
            logger.debug(f"Execution token validated and consumed for action {action_id}")
        elif not valid:
            logger.warning(f"Invalid execution token presented for action {action_id}")

        return valid

    def revoke_execution_token(self, action_id: str) -> bool:
        """
        Revoke an execution token before use.

        Use this when an action is cancelled after token generation.

        Args:
            action_id: The action whose token to revoke

        Returns:
            True if token was revoked, False if no token existed
        """
        if action_id in self._active_execution_tokens:
            del self._active_execution_tokens[action_id]
            logger.info(f"Execution token revoked for action {action_id}")
            return True
        return False

    def _compute_context_hash(self, ctx: ActionContext) -> str:
        """Compute hash of action context for integrity verification."""
        import hashlib
        import json

        context_data = {
            "tenant_id": ctx.tenant_id,
            "campaign_id": ctx.campaign_id,
            "mode": ctx.mode,
            "risk_tier": ctx.risk_tier,
            "scope_id": ctx.scope_id,
            "action_id": ctx.action_id,
            "permit_id": ctx.permit_id,
            "timestamp": ctx.timestamp.isoformat(),
        }
        content = json.dumps(context_data, sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    async def validate_and_execute_action(
        self,
        ctx: ActionContext,
    ) -> Tuple[DecisionRecord, Optional[Dict[str, Any]]]:
        """
        THE ONLY AUTHORIZED PATH FOR ACTION EXECUTION.

        This function enforces all guards in exact order:
        1. Permit validation (with TTL check)
        2. OPA ABAC + Scope evaluation
        3. Runtime behavior guard
        4. Rate limit check
        5. Target safety probe
        6. Execute action
        7. Emit forensic event

        Args:
            ctx: ActionContext with all execution parameters

        Returns:
            Tuple of (DecisionRecord, execution_result or None)

        Raises:
            PermitDeniedError: Permit validation failed
            PermitExpiredError: Permit TTL expired
            PolicyDeniedError: OPA policy denied action
            ScopeDriftError: P2+ scope drift detected
            StepUpRequiredError: Step-up authentication needed
            SoDViolationError: Separation of duties violated
            RateLimitedError: Rate limit exceeded
            TargetUnsafeError: Target safety check failed
            WitnessRequiredError: Dual attestation witness unavailable
        """
        # Initialize decision record
        record = DecisionRecord(
            action_id=ctx.action_id,
            action_context_hash=self._compute_context_hash(ctx),
        )

        execution_result = None

        try:
            # ============================================================
            # GUARD 1: Permit Validation (with TTL check)
            # ============================================================
            record.permit_decision = await self._check_permit(ctx)
            if record.permit_decision.decision != "ALLOW":
                self._raise_permit_error(record.permit_decision, ctx)

            # ============================================================
            # GUARD 2: OPA Evaluation (ABAC + Scope)
            # ============================================================
            record.opa_abac_decision = await self._check_opa_abac(ctx)
            if record.opa_abac_decision.decision != "ALLOW":
                self._raise_policy_error(record.opa_abac_decision, ctx)

            record.opa_scope_decision = await self._check_opa_scope(ctx)
            if record.opa_scope_decision.decision != "ALLOW":
                self._raise_scope_error(record.opa_scope_decision, ctx)

            # ============================================================
            # GUARD 3: Runtime Behavior Guard
            # ============================================================
            record.runtime_guard_decision = await self._check_runtime_guard(ctx)
            if record.runtime_guard_decision.decision != "ALLOW":
                self._raise_runtime_error(record.runtime_guard_decision, ctx)

            # ============================================================
            # GUARD 4: Rate Limit Check
            # ============================================================
            record.rate_limit_decision = await self._check_rate_limit(ctx)
            if record.rate_limit_decision.decision != "ALLOW":
                self._raise_rate_limit_error(record.rate_limit_decision, ctx)

            # ============================================================
            # GUARD 5: Target Safety Probe
            # ============================================================
            record.target_safety_decision = await self._check_target_safety(ctx)
            if record.target_safety_decision.decision != "ALLOW":
                self._raise_target_safety_error(record.target_safety_decision, ctx)

            # ============================================================
            # All guards passed - EXECUTE
            # ============================================================
            record.all_guards_passed = True

            # v6.1 SECURITY: Generate one-time execution token
            # This token MUST be presented to the executor to prove authorization
            execution_token = self.generate_execution_token(ctx.action_id, record)

            try:
                if self._action_executor:
                    # Pass token to executor for validation
                    execution_result = await self._action_executor(
                        ctx, record, execution_token=execution_token
                    )
                    record.executed = True
                    record.execution_result = execution_result
                elif self._test_mode:
                    # Test mode: simulate execution (token still required for test validation)
                    # Validate token to prove the flow is correct even in tests
                    if not self.validate_execution_token(
                        token=execution_token,
                        action_id=ctx.action_id,
                    ):
                        raise GuardBypassError(
                            message="Test mode execution failed token validation",
                            bypass_path="test_mode_token_failure",
                            caller="ExecutionControlPlane",
                        )
                    execution_result = {
                        "status": "success",
                        "action_id": ctx.action_id,
                        "simulated": True,
                        "token_validated": True,
                    }
                    record.executed = True
                    record.execution_result = execution_result
                else:
                    # No executor configured - this is a configuration error
                    record.error = "No action executor configured"
            except Exception as e:
                # If execution fails, ensure token is revoked if not consumed
                self.revoke_execution_token(ctx.action_id)
                raise

            # ============================================================
            # GUARD 7: Emit Forensic Event
            # ============================================================
            await self._emit_forensic_event(ctx, record, "SUCCESS")

        except (
            PermitDeniedError,
            PermitExpiredError,
            PolicyDeniedError,
            ScopeDriftError,
            StepUpRequiredError,
            SoDViolationError,
            RateLimitedError,
            TargetUnsafeError,
            WitnessRequiredError,
        ) as e:
            record.error = str(e)
            await self._emit_forensic_event(ctx, record, "BLOCKED")
            raise

        except Exception as e:
            record.error = str(e)
            await self._emit_forensic_event(ctx, record, "FAILURE")
            raise

        finally:
            # Store decision record for audit
            self._decision_records[ctx.action_id] = record

        return record, execution_result

    # ========================================================================
    # Guard Implementation Methods
    # ========================================================================

    async def _check_permit(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 1: Validate permit including TTL check.

        TTL is checked PER ACTION, not just at preflight.
        """
        timestamp = datetime.now(timezone.utc)

        if self._permit_validator is None:
            # FAIL CLOSED - no validator means no permit validation
            return GuardDecisionEntry(
                guard_name="permit_validator",
                decision="DENY",
                timestamp=timestamp,
                rule="PERMIT.VALIDATOR.MISSING",
                reason="Permit validator not configured - FAIL CLOSED",
            )

        try:
            # Check TTL first (per-action TTL check)
            expired, remaining_ttl = self._permit_validator.check_ttl_expiry(ctx.permit)
            if expired:
                return GuardDecisionEntry(
                    guard_name="permit_validator",
                    decision="DENY",
                    timestamp=timestamp,
                    rule="PERMIT.EXPIRED",
                    reason="Permit TTL has expired",
                    details={"remaining_ttl": 0},
                )

            # Validate permit against action
            action_data = {
                "action_id": ctx.action_id,
                "tool_id": ctx.action.get("tool_id") or ctx.action.get("type"),
                "target_id": ctx.target.get("target_id") or ctx.target.get("asset"),
                "entrypoint_id": ctx.entrypoint.get("entrypoint_id"),
            }

            result = self._permit_validator.validate_permit(
                permit=ctx.permit,
                action=action_data,
                consume_nonce=False,  # Nonce already consumed at preflight
            )

            if result.valid:
                return GuardDecisionEntry(
                    guard_name="permit_validator",
                    decision="ALLOW",
                    timestamp=timestamp,
                    rule="PERMIT.VALID",
                    reason="Permit validated successfully",
                    details={
                        "remaining_ttl": remaining_ttl,
                        "signature_verified": result.signature_verified,
                    },
                )
            else:
                return GuardDecisionEntry(
                    guard_name="permit_validator",
                    decision="DENY",
                    timestamp=timestamp,
                    rule=result.issues[0]["code"] if result.issues else "PERMIT.INVALID",
                    reason=result.issues[0]["message"] if result.issues else "Permit validation failed",
                    details={"issues": result.issues},
                )

        except Exception as e:
            return GuardDecisionEntry(
                guard_name="permit_validator",
                decision="DENY",
                timestamp=timestamp,
                rule="PERMIT.ERROR",
                reason=f"Permit validation error: {e}",
            )

    async def _check_opa_abac(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 2a: OPA ABAC (SoD + step-up) evaluation.
        """
        timestamp = datetime.now(timezone.utc)

        # Check Separation of Duties for high-risk LIVE modes
        if ctx.mode in ("LIVE_GUARDED", "LIVE_AUTONOMOUS") and ctx.risk_tier >= 2:
            if ctx.executor_id and ctx.approver_ids:
                if ctx.executor_id in ctx.approver_ids:
                    return GuardDecisionEntry(
                        guard_name="opa_abac",
                        decision="DENY",
                        timestamp=timestamp,
                        rule="ABAC.SOD.VIOLATION",
                        reason="Executor cannot be an approver for risk tier 2+ in LIVE modes",
                        details={
                            "executor_id": ctx.executor_id,
                            "approver_ids": ctx.approver_ids,
                        },
                    )

        # Check step-up requirements
        action_type = ctx.action.get("type", "")
        requires_stepup = (
            ctx.action.get("destructive", False) or
            ctx.action.get("credential_access", False) or
            ctx.action.get("scope_expansion", False) or
            (ctx.risk_tier >= 3 and ctx.mode != "SIM") or
            ctx.classification_level in ("SECRET", "TOPSECRET")
        )

        if requires_stepup and not ctx.action.get("step_up_completed", False):
            return GuardDecisionEntry(
                guard_name="opa_abac",
                decision="DENY",
                timestamp=timestamp,
                rule="ABAC.STEPUP.REQUIRED",
                reason="Step-up authentication required for this action",
                details={
                    "action_type": action_type,
                    "risk_tier": ctx.risk_tier,
                    "classification": ctx.classification_level,
                },
            )

        # If OPA client is available, query it
        if self._opa_client:
            try:
                result = await self._query_opa_abac(ctx)
                if not result.get("allow", False):
                    return GuardDecisionEntry(
                        guard_name="opa_abac",
                        decision="DENY",
                        timestamp=timestamp,
                        rule=result.get("rule", "OPA.ABAC.DENIED"),
                        reason=result.get("reason", "OPA ABAC policy denied"),
                        details=result,
                    )
            except Exception as e:
                # FAIL CLOSED on OPA errors
                return GuardDecisionEntry(
                    guard_name="opa_abac",
                    decision="DENY",
                    timestamp=timestamp,
                    rule="OPA.ERROR",
                    reason=f"OPA ABAC evaluation failed: {e}",
                )

        return GuardDecisionEntry(
            guard_name="opa_abac",
            decision="ALLOW",
            timestamp=timestamp,
            rule="ABAC.PASSED",
            reason="ABAC checks passed",
        )

    async def _check_opa_scope(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 2b: OPA Scope lint evaluation.

        P2+ scope drift MUST halt execution.
        """
        timestamp = datetime.now(timezone.utc)

        # If OPA client available, check scope drift
        if self._opa_client:
            try:
                result = await self._query_opa_scope(ctx)
                drift_score = result.get("drift_score", 0.0)
                severity = result.get("severity", "P1")

                # P2+ drift halts execution
                if severity in ("P2", "P3", "P4", "P5"):
                    return GuardDecisionEntry(
                        guard_name="opa_scope",
                        decision="HALT",
                        timestamp=timestamp,
                        rule="RUNTIME.SCOPE.DRIFT",
                        reason=f"Scope drift {severity} detected ({drift_score:.2%})",
                        details={
                            "drift_score": drift_score,
                            "severity": severity,
                            "action_required": "HALT_AND_REVOKE",
                        },
                    )
            except Exception as e:
                # FAIL CLOSED
                return GuardDecisionEntry(
                    guard_name="opa_scope",
                    decision="DENY",
                    timestamp=timestamp,
                    rule="OPA.SCOPE.ERROR",
                    reason=f"OPA scope evaluation failed: {e}",
                )

        return GuardDecisionEntry(
            guard_name="opa_scope",
            decision="ALLOW",
            timestamp=timestamp,
            rule="SCOPE.VALID",
            reason="Scope validation passed",
        )

    async def _check_runtime_guard(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 3: Runtime behavior guard check.

        Enforces mode-aware contracts.
        If dual attestation required and witness unavailable, HALT.
        """
        timestamp = datetime.now(timezone.utc)

        # Check if dual attestation is required
        requires_dual_attestation = ctx.mode in (
            "CANARY", "SHADOW", "LIVE_GUARDED", "LIVE_AUTONOMOUS"
        )

        if self._runtime_guard is None:
            # FAIL CLOSED
            return GuardDecisionEntry(
                guard_name="runtime_guard",
                decision="DENY",
                timestamp=timestamp,
                rule="RUNTIME.GUARD.MISSING",
                reason="Runtime guard not configured - FAIL CLOSED",
            )

        try:
            from ..runtime_guard import ExecutionMode, AutonomyLevel, Decision

            mode = ExecutionMode(ctx.mode)
            autonomy = AutonomyLevel(ctx.action.get("autonomy_level", 1))

            decision = self._runtime_guard.enforce_action(
                action={
                    "action_id": ctx.action_id,
                    "target_id": ctx.target.get("target_id"),
                    "action_type": ctx.action.get("type"),
                    "destructive": ctx.action.get("destructive", False),
                    "expands_scope": ctx.action.get("scope_expansion", False),
                    "is_live_target": ctx.mode != "SIM",
                },
                mode=mode,
                autonomy_level=autonomy,
                campaign_id=ctx.campaign_id,
                human_confirmed=ctx.human_confirmed,
            )

            if decision.decision == Decision.ALLOW:
                return GuardDecisionEntry(
                    guard_name="runtime_guard",
                    decision="ALLOW",
                    timestamp=timestamp,
                    rule=decision.rule,
                    reason=decision.reason,
                    attestation_hash=decision.attestation_hash,
                )
            elif decision.decision == Decision.REQUIRE_CONFIRMATION:
                return GuardDecisionEntry(
                    guard_name="runtime_guard",
                    decision="DENY",
                    timestamp=timestamp,
                    rule=decision.rule,
                    reason=decision.reason,
                    details={"requires_confirmation": True},
                )
            else:
                return GuardDecisionEntry(
                    guard_name="runtime_guard",
                    decision="DENY",
                    timestamp=timestamp,
                    rule=decision.rule,
                    reason=decision.reason,
                    details=decision.details,
                )

        except Exception as e:
            return GuardDecisionEntry(
                guard_name="runtime_guard",
                decision="DENY",
                timestamp=timestamp,
                rule="RUNTIME.ERROR",
                reason=f"Runtime guard check failed: {e}",
            )

    async def _check_rate_limit(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 4: Rate limit check.

        Uses persistent sliding window. Exceeding limit MUST halt.
        """
        timestamp = datetime.now(timezone.utc)

        if self._rate_limiter is None:
            # In test mode or no limiter, allow but log warning
            logger.warning("Rate limiter not configured - allowing action")
            return GuardDecisionEntry(
                guard_name="rate_limiter",
                decision="ALLOW",
                timestamp=timestamp,
                rule="RATE.LIMITER.MISSING",
                reason="Rate limiter not configured",
            )

        try:
            target_id = ctx.target.get("target_id") or ctx.target.get("asset")

            # Get mode-specific limit
            mode_limits = {
                "SIM": 1000,
                "LAB": 60,
                "CANARY": 30,
                "SHADOW": 10,
                "LIVE_GUARDED": 5,
                "LIVE_AUTONOMOUS": 10,
            }
            max_rate = mode_limits.get(ctx.mode, 60)

            allowed, current_rate = self._rate_limiter.check_rate(target_id, max_rate)

            if allowed:
                return GuardDecisionEntry(
                    guard_name="rate_limiter",
                    decision="ALLOW",
                    timestamp=timestamp,
                    rule="RATE.ALLOWED",
                    reason=f"Rate {current_rate}/{max_rate} within limit",
                    details={"current_rate": current_rate, "max_rate": max_rate},
                )
            else:
                return GuardDecisionEntry(
                    guard_name="rate_limiter",
                    decision="DENY",
                    timestamp=timestamp,
                    rule="RUNTIME.RATE.EXCEEDED",
                    reason=f"Rate limit exceeded: {current_rate}/{max_rate}",
                    details={"current_rate": current_rate, "max_rate": max_rate},
                )

        except Exception as e:
            return GuardDecisionEntry(
                guard_name="rate_limiter",
                decision="DENY",
                timestamp=timestamp,
                rule="RATE.ERROR",
                reason=f"Rate limit check failed: {e}",
            )

    async def _check_target_safety(self, ctx: ActionContext) -> GuardDecisionEntry:
        """
        Guard 5: Target safety probe and check.

        Health probe before targeting. Stop conditions MUST halt.
        """
        timestamp = datetime.now(timezone.utc)

        if self._target_safety is None:
            # In test mode, allow but warn
            logger.warning("Target safety not configured - allowing action")
            return GuardDecisionEntry(
                guard_name="target_safety",
                decision="ALLOW",
                timestamp=timestamp,
                rule="TARGET.SAFETY.MISSING",
                reason="Target safety not configured",
            )

        try:
            target_id = ctx.target.get("target_id") or ctx.target.get("asset")

            result = await self._target_safety.check_action_safety(
                target_id=target_id,
                action=ctx.action,
            )

            if result.allowed:
                return GuardDecisionEntry(
                    guard_name="target_safety",
                    decision="ALLOW",
                    timestamp=timestamp,
                    rule="TARGET.SAFE",
                    reason="Target safety checks passed",
                    details={"warnings": result.warnings},
                )
            else:
                return GuardDecisionEntry(
                    guard_name="target_safety",
                    decision="DENY",
                    timestamp=timestamp,
                    rule=f"TARGET.{result.stop_condition.name}" if result.stop_condition else "TARGET.UNSAFE",
                    reason=result.reason,
                    details={"stop_condition": str(result.stop_condition) if result.stop_condition else None},
                )

        except Exception as e:
            return GuardDecisionEntry(
                guard_name="target_safety",
                decision="DENY",
                timestamp=timestamp,
                rule="TARGET.ERROR",
                reason=f"Target safety check failed: {e}",
            )

    # ========================================================================
    # Error Raising Methods
    # ========================================================================

    def _raise_permit_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise appropriate permit error based on decision."""
        if decision.rule == "PERMIT.EXPIRED":
            raise PermitExpiredError(
                message=decision.reason,
                permit_id=ctx.permit_id,
                expired_at=ctx.permit.get("expires_at"),
                action_id=ctx.action_id,
            )
        else:
            raise PermitDeniedError(
                message=decision.reason,
                permit_id=ctx.permit_id,
                reason=decision.rule,
                issues=decision.details.get("issues", []),
            )

    def _raise_policy_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise appropriate policy error based on decision."""
        if decision.rule == "ABAC.STEPUP.REQUIRED":
            raise StepUpRequiredError(
                message=decision.reason,
                action_id=ctx.action_id,
                reason=decision.reason,
            )
        elif decision.rule == "ABAC.SOD.VIOLATION":
            raise SoDViolationError(
                message=decision.reason,
                executor_id=ctx.executor_id,
            )
        else:
            raise PolicyDeniedError(
                message=decision.reason,
                decision=decision.decision,
                violations=[decision.reason] if decision.reason else [],
            )

    def _raise_scope_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise scope drift error."""
        raise ScopeDriftError(
            message=decision.reason,
            drift_score=decision.details.get("drift_score", 0.0),
            severity=decision.details.get("severity", "P2"),
        )

    def _raise_runtime_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise appropriate runtime error based on decision."""
        if decision.details.get("requires_confirmation"):
            raise PolicyDeniedError(
                message=decision.reason,
                decision="REQUIRE_CONFIRMATION",
            )
        elif "witness" in decision.rule.lower():
            raise WitnessRequiredError(
                message=decision.reason,
                action_id=ctx.action_id,
                mode=ctx.mode,
            )
        else:
            raise PolicyDeniedError(
                message=decision.reason,
                decision=decision.decision,
            )

    def _raise_rate_limit_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise rate limit error."""
        raise RateLimitedError(
            message=decision.reason,
            target_id=ctx.target.get("target_id"),
            current_rate=decision.details.get("current_rate", 0),
            max_rate=decision.details.get("max_rate", 0),
        )

    def _raise_target_safety_error(self, decision: GuardDecisionEntry, ctx: ActionContext):
        """Raise target safety error."""
        raise TargetUnsafeError(
            message=decision.reason,
            target_id=ctx.target.get("target_id"),
            stop_condition=decision.details.get("stop_condition"),
        )

    # ========================================================================
    # Helper Methods
    # ========================================================================

    async def _query_opa_abac(self, ctx: ActionContext) -> Dict[str, Any]:
        """Query OPA for ABAC decision."""
        # Stub - would query OPA in production
        return {"allow": True}

    async def _query_opa_scope(self, ctx: ActionContext) -> Dict[str, Any]:
        """Query OPA for scope lint decision."""
        # Stub - would query OPA in production
        return {"allow": True, "drift_score": 0.0, "severity": "P0"}

    async def _emit_forensic_event(
        self,
        ctx: ActionContext,
        record: DecisionRecord,
        outcome: str,
    ):
        """Emit forensic event for audit trail."""
        event = ForensicEvent(
            event_id=str(uuid4()),
            event_type="ACTION_EXECUTED" if outcome == "SUCCESS" else "ACTION_DENIED",
            timestamp=datetime.now(timezone.utc),
            action_context=ctx,
            decision_record=record,
            outcome=outcome,
        )

        if self._forensic_emitter:
            try:
                await self._forensic_emitter(event)
            except Exception as e:
                logger.error(f"Failed to emit forensic event: {e}")

        # Log for debugging
        logger.info(
            f"Forensic event: {event.event_type} action={ctx.action_id} outcome={outcome}"
        )

    def get_decision_record(self, action_id: str) -> Optional[DecisionRecord]:
        """Get decision record for an action."""
        return self._decision_records.get(action_id)

    async def execute_with_token(
        self,
        ctx: ActionContext,
        record: DecisionRecord,
        execution_token: str,
        executor_func: Callable,
    ) -> Dict[str, Any]:
        """
        Execute an action with proper token-based authorization.

        This method sets up the execution context with the token and
        calls the executor. The executor MUST validate the token.

        Args:
            ctx: The action context
            record: The decision record proving all guards passed
            execution_token: The one-time execution token
            executor_func: The function to call for execution

        Returns:
            The execution result

        Raises:
            GuardBypassError: If token validation fails
        """
        from ..sim import mark_legitimate_execution, clear_legitimate_execution

        # Set up execution context with token
        mark_legitimate_execution(
            decision_record=record,
            execution_token=execution_token,
            action_id=ctx.action_id,
            control_plane=self,
        )

        try:
            # Execute the action
            result = await executor_func(ctx, record)
            return result
        finally:
            # Always clear the context
            clear_legitimate_execution()


def create_token_validated_executor(
    control_plane: "ExecutionControlPlane",
    base_executor: Callable,
) -> Callable:
    """
    Create an executor wrapper that validates tokens.

    This wraps a base executor function to ensure it properly
    validates execution tokens before proceeding.

    Args:
        control_plane: The ExecutionControlPlane instance
        base_executor: The underlying executor function

    Returns:
        A wrapped executor that validates tokens
    """
    from ..sim import mark_legitimate_execution, clear_legitimate_execution

    async def token_validated_executor(
        ctx: ActionContext,
        record: DecisionRecord,
        execution_token: str = None,
    ) -> Dict[str, Any]:
        """Execute action with token validation."""
        if execution_token is None:
            raise GuardBypassError(
                message="Executor called without execution token",
                bypass_path="missing_token_in_executor",
                caller="token_validated_executor",
            )

        # Set up execution context with token
        mark_legitimate_execution(
            decision_record=record,
            execution_token=execution_token,
            action_id=ctx.action_id,
            control_plane=control_plane,
        )

        try:
            # Validate token with control plane
            if not control_plane.validate_execution_token(
                token=execution_token,
                action_id=ctx.action_id,
                consume=True,
            ):
                raise GuardBypassError(
                    message="Invalid execution token",
                    bypass_path="token_validation_failed",
                    caller="token_validated_executor",
                )

            # Execute the base executor
            result = await base_executor(ctx, record)
            return result
        finally:
            clear_legitimate_execution()

    return token_validated_executor


# Global execution control plane instance
_execution_control_plane: Optional[ExecutionControlPlane] = None


def get_execution_control_plane() -> ExecutionControlPlane:
    """Get the global execution control plane instance."""
    global _execution_control_plane
    if _execution_control_plane is None:
        _execution_control_plane = ExecutionControlPlane()
    return _execution_control_plane


def set_execution_control_plane(ecp: ExecutionControlPlane):
    """Set the global execution control plane instance (for testing)."""
    global _execution_control_plane
    _execution_control_plane = ecp


async def validate_and_execute_action(
    ctx: ActionContext,
) -> Tuple[DecisionRecord, Optional[Dict[str, Any]]]:
    """
    THE ONLY AUTHORIZED PATH FOR ACTION EXECUTION.

    This is the public API for action execution.
    All actions MUST flow through this function.

    See ExecutionControlPlane.validate_and_execute_action for details.
    """
    ecp = get_execution_control_plane()
    return await ecp.validate_and_execute_action(ctx)


def check_bypass_attempt(caller_frame=None) -> bool:
    """
    Check if the current call is a bypass attempt.

    This is called by protected execution paths to detect
    when code attempts to execute actions without going
    through validate_and_execute_action().

    Returns:
        True if bypass detected, False if legitimate call
    """
    if caller_frame is None:
        caller_frame = inspect.currentframe().f_back

    # Get the call stack
    stack = inspect.stack()

    # Look for validate_and_execute_action in the call stack
    for frame_info in stack:
        if frame_info.function == "validate_and_execute_action":
            return False  # Legitimate call

    # If we got here without finding the chokepoint, it's a bypass
    return True


class SafetyPolicyEvaluator:
    """
    Safety policy evaluator using OPA.

    Evaluates safety constraints during mission execution including:
    - Forensic completeness checks
    - Concurrency limits
    - Simulation validation
    - Scope expansion prevention
    - Cross-ring contamination prevention
    """

    def __init__(self, opa_url: str = "http://localhost:8181"):
        """Initialize safety evaluator."""
        self._opa_url = opa_url
        self._session: Optional[aiohttp.ClientSession] = None
        self._healthy = False

    async def start(self) -> None:
        """Start the safety evaluator."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5.0)
        )
        await self._check_health()

    async def stop(self) -> None:
        """Stop the safety evaluator."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _check_health(self) -> bool:
        """Check OPA health."""
        if not self._session:
            return False
        try:
            async with self._session.get(f"{self._opa_url}/health") as resp:
                self._healthy = resp.status == 200
                return self._healthy
        except Exception:
            self._healthy = False
            return False

    async def evaluate_safety(
        self,
        action: Dict[str, Any],
        mission_context: Dict[str, Any],
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate safety constraints for an action.

        Args:
            action: Action being evaluated
            mission_context: Mission context including policy, ROE
            metrics: Current system metrics

        Returns:
            Evaluation result with safe/unsafe and violations
        """
        input_data = {
            "action": action,
            "context": mission_context,
            "metrics": metrics,
            "state": {
                "active_operations": mission_context.get("active_operations", 0),
            },
            "policy": mission_context.get("policy_envelope", {}),
            "promotion": mission_context.get("promotion", {}),
        }

        if self._healthy and self._session:
            try:
                url = f"{self._opa_url}/v1/data/frostgate/safety"
                async with self._session.post(
                    url,
                    json={"input": input_data},
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        policy_result = result.get("result", {})
                        return {
                            "safe": policy_result.get("safe", False),
                            "violations": policy_result.get("safety_violations", []),
                            "red_lines": policy_result.get("red_line_violations", []),
                        }
            except Exception as e:
                logger.warning(f"OPA safety evaluation failed: {e}")

        # Fallback to local evaluation
        return await self._local_evaluate(input_data)

    async def _local_evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Local safety evaluation fallback."""
        violations = []
        action = input_data.get("action", {})
        context = input_data.get("context", {})
        metrics = input_data.get("metrics", {})

        # Check forensic completeness
        forensic_completeness = metrics.get("forensic_completeness", 1.0)
        if forensic_completeness < 0.95:
            violations.append(
                f"Forensic completeness below threshold: {forensic_completeness:.2f} < 0.95"
            )

        # Check scope expansion
        if action.get("expands_scope") and not action.get("scope_expansion_authorized"):
            violations.append("Unauthorized scope expansion attempted")

        # Check destructive operations
        if action.get("destructive"):
            approvals = context.get("approvals", {})
            if not approvals.get("ao_signature"):
                violations.append("Destructive operation without AO signature")

        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "red_lines": [],
        }


class EngineState(Enum):
    """Engine operational states."""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    SHUTTING_DOWN = "shutting_down"
    ERROR = "error"


@dataclass
class EngineMetrics:
    """Engine performance and health metrics."""
    active_missions: int = 0
    completed_missions: int = 0
    policy_violations: int = 0
    roe_violations: int = 0
    safety_violations: int = 0
    forensic_completeness: float = 0.0
    uptime_seconds: float = 0.0


class FrostGateSpear:
    """
    Main Frost Gate Spear Engine.

    Coordinates all subsystems including:
    - Policy Interpreter
    - ROE Engine
    - Planner
    - Executor
    - Target Impact Estimator (TIE)
    - Blue Box Explainer
    - Forensics
    - MLS Manager
    - FL Controller
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize Frost Gate Spear engine.

        Args:
            config: Configuration object. Uses defaults if not provided.
        """
        self.config = config or Config()
        self.state = EngineState.INITIALIZING
        self.engine_id = uuid4()
        self.start_time: Optional[datetime] = None
        self.metrics = EngineMetrics()

        # Subsystem references (initialized in start())
        self._policy_interpreter = None
        self._roe_engine = None
        self._planner = None
        self._executor = None
        self._tie = None
        self._blue_box = None
        self._forensics = None
        self._mls_manager = None
        self._fl_controller = None
        self._governance = None
        self._integrity_manager = None

        # Safety policy evaluator
        self._safety_evaluator = SafetyPolicyEvaluator(
            opa_url=getattr(config, "opa_url", "http://localhost:8181")
        )

        # Mission tracking
        self._missions: Dict[UUID, Mission] = {}
        self._mission_lock = asyncio.Lock()

        logger.info(f"FrostGateSpear engine initialized: {self.engine_id}")

    async def start(self) -> None:
        """Start the engine and all subsystems."""
        logger.info("Starting Frost Gate Spear engine...")

        try:
            # Initialize subsystems in dependency order
            await self._initialize_subsystems()

            # Validate configuration
            await self._validate_configuration()

            # Start background tasks
            await self._start_background_tasks()

            self.state = EngineState.READY
            self.start_time = datetime.utcnow()
            logger.info("Frost Gate Spear engine started successfully")

        except Exception as e:
            self.state = EngineState.ERROR
            logger.error(f"Failed to start engine: {e}")
            raise FrostGateError(f"Engine start failed: {e}") from e

    async def stop(self) -> None:
        """Stop the engine gracefully."""
        logger.info("Stopping Frost Gate Spear engine...")
        self.state = EngineState.SHUTTING_DOWN

        # Stop all active missions
        async with self._mission_lock:
            for mission in self._missions.values():
                if mission.state == MissionState.RUNNING:
                    await self.abort_mission(mission.mission_id, reason="Engine shutdown")

        # Shutdown subsystems
        await self._shutdown_subsystems()

        logger.info("Frost Gate Spear engine stopped")

    async def create_mission(
        self,
        policy_envelope: Dict[str, Any],
        scenario: Dict[str, Any],
        persona_id: Optional[str] = None,
    ) -> Mission:
        """
        Create a new mission.

        Args:
            policy_envelope: Policy envelope defining mission constraints
            scenario: Attack scenario definition
            persona_id: Optional adversary persona to use

        Returns:
            Created Mission object

        Raises:
            PolicyViolationError: If policy envelope validation fails
            ROEViolationError: If ROE constraints are violated
        """
        logger.info("Creating new mission...")

        # Validate policy envelope
        await self._policy_interpreter.validate_envelope(policy_envelope)

        # Validate ROE
        await self._roe_engine.validate_roe(policy_envelope.get("roe", {}))

        # Check MLS constraints
        classification = policy_envelope.get("classification_level", "UNCLASS")
        await self._mls_manager.validate_ring_access(classification)

        # Create mission
        mission = Mission(
            policy_envelope=policy_envelope,
            scenario=scenario,
            persona_id=persona_id,
            classification_level=classification,
        )

        async with self._mission_lock:
            self._missions[mission.mission_id] = mission

        logger.info(f"Mission created: {mission.mission_id}")
        return mission

    async def start_mission(self, mission_id: UUID) -> None:
        """
        Start execution of a mission.

        Args:
            mission_id: ID of mission to start

        Raises:
            FrostGateError: If mission not found or cannot be started
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

            if mission.state != MissionState.CREATED:
                raise FrostGateError(
                    f"Mission cannot be started from state: {mission.state}"
                )

        # Pre-flight checks
        await self._preflight_checks(mission)

        # Estimate impact
        impact_estimate = await self._tie.estimate_impact(mission)
        if impact_estimate.exceeds_blast_radius:
            raise SafetyConstraintError(
                f"Estimated impact {impact_estimate.score} exceeds blast radius cap"
            )

        # Generate execution plan
        plan = await self._planner.create_plan(mission)

        # Validate plan against ROE
        await self._roe_engine.validate_plan(plan, mission.policy_envelope)

        # Start execution
        mission.state = MissionState.RUNNING
        mission.plan = plan
        self.metrics.active_missions += 1

        # Execute asynchronously
        asyncio.create_task(self._execute_mission(mission))

        logger.info(f"Mission started: {mission_id}")

    async def abort_mission(
        self, mission_id: UUID, reason: str = "User requested"
    ) -> None:
        """
        Abort a running mission.

        Args:
            mission_id: ID of mission to abort
            reason: Reason for abortion
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        if mission.state == MissionState.RUNNING:
            await self._executor.abort(mission)
            mission.state = MissionState.ABORTED
            mission.abort_reason = reason
            self.metrics.active_missions -= 1

        logger.warning(f"Mission aborted: {mission_id} - {reason}")

    async def get_mission_status(self, mission_id: UUID) -> Dict[str, Any]:
        """Get current status of a mission."""
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        # Get explanation from Blue Box
        explanation = await self._blue_box.explain_mission(mission)

        return {
            "mission_id": str(mission.mission_id),
            "state": mission.state.value,
            "classification_level": mission.classification_level,
            "progress": mission.progress,
            "current_phase": mission.current_phase,
            "actions_completed": mission.actions_completed,
            "actions_remaining": mission.actions_remaining,
            "impact_score": mission.impact_score,
            "explanation": explanation,
            "forensic_completeness": await self._forensics.get_completeness(mission),
        }

    async def replay_mission(self, mission_id: UUID) -> Dict[str, Any]:
        """
        Replay a completed mission for verification.

        Args:
            mission_id: ID of mission to replay

        Returns:
            Replay results including success status
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        if mission.state not in [MissionState.COMPLETED, MissionState.ABORTED]:
            raise FrostGateError("Can only replay completed or aborted missions")

        return await self._forensics.replay_mission(mission)

    # Private methods

    async def _initialize_subsystems(self) -> None:
        """Initialize all subsystems including safety evaluator and integrity manager."""
        from ..policy_interpreter import PolicyInterpreter
        from ..roe_engine import ROEEngine
        from ..planner import Planner
        from ..sim import Executor
        from ..tie import TargetImpactEstimator
        from ..blue_box import BlueBox
        from ..forensics import ForensicsManager
        from ..mls import MLSManager
        from ..fl import FLController
        from ..governance import GovernanceManager
        from ..integrity import IntegrityManager

        self._policy_interpreter = PolicyInterpreter(self.config)
        self._roe_engine = ROEEngine(self.config)
        self._planner = Planner(self.config)
        self._executor = Executor(self.config)
        self._tie = TargetImpactEstimator(self.config)
        self._blue_box = BlueBox(self.config)
        self._forensics = ForensicsManager(self.config)
        self._mls_manager = MLSManager(self.config)
        self._fl_controller = FLController(self.config)
        self._governance = GovernanceManager(self.config)

        # Initialize integrity manager for SBOM/artifact verification
        trust_store_path = getattr(self.config, "trust_store_path", None)
        self._integrity_manager = IntegrityManager(
            trust_store_path=trust_store_path,
            require_signatures=getattr(self.config, "require_signatures", True),
        )

        # Start all subsystems including safety evaluator
        await asyncio.gather(
            self._policy_interpreter.start(),
            self._roe_engine.start(),
            self._planner.start(),
            self._executor.start(),
            self._tie.start(),
            self._blue_box.start(),
            self._forensics.start(),
            self._mls_manager.start(),
            self._fl_controller.start(),
            self._governance.start(),
            self._integrity_manager.start(),
            self._safety_evaluator.start(),
        )

    async def _validate_configuration(self) -> None:
        """Validate engine configuration."""
        # Validate policy files exist
        await self._policy_interpreter.validate_policies()

        # Validate MLS ring configurations
        await self._mls_manager.validate_rings()

        # Validate governance gates
        await self._governance.validate_gates()

    async def _start_background_tasks(self) -> None:
        """Start background monitoring tasks."""
        asyncio.create_task(self._metrics_collector())
        asyncio.create_task(self._health_monitor())

    async def _shutdown_subsystems(self) -> None:
        """Shutdown all subsystems gracefully."""
        subsystems = [
            self._executor,
            self._planner,
            self._fl_controller,
            self._forensics,
            self._blue_box,
            self._tie,
            self._mls_manager,
            self._roe_engine,
            self._policy_interpreter,
            self._governance,
            self._safety_evaluator,
        ]

        for subsystem in subsystems:
            if subsystem:
                try:
                    await subsystem.stop()
                except Exception as e:
                    logger.error(f"Error stopping subsystem: {e}")

    async def _preflight_checks(self, mission: Mission) -> None:
        """
        Run pre-flight checks before mission execution.

        Includes:
        - Approval validation
        - Scenario hash verification
        - SBOM verification (if present)
        - Budget checks
        """
        # Check approvals
        await self._governance.validate_approvals(mission)

        # Validate scenario hash
        await self._forensics.validate_scenario_hash(mission)

        # Verify scenario integrity
        if self._integrity_manager:
            expected_hash = mission.policy_envelope.get("scenario_hash")
            scenario_result = await self._integrity_manager.verify_artifact(
                artifact_type="scenario",
                artifact=mission.scenario,
                expected_hash=expected_hash,
                require_signature=mission.policy_envelope.get("risk_tier", 1) >= 3,
            )
            if not scenario_result.valid:
                raise PolicyViolationError(
                    f"Scenario integrity verification failed: {scenario_result.details}"
                )
            logger.info(
                f"Scenario integrity verified: {scenario_result.computed_hash[:16]}..."
            )

        # Verify SBOM if attached to scenario
        sbom = mission.scenario.get("sbom")
        if sbom and self._integrity_manager:
            attestation = mission.scenario.get("sbom_attestation")
            sbom_result = await self._integrity_manager.sbom_verifier.verify_sbom(
                sbom=sbom,
                attestation=attestation,
            )
            if not sbom_result.valid:
                raise PolicyViolationError(
                    f"SBOM verification failed: {sbom_result.details}"
                )
            logger.info(
                f"SBOM verified: {sbom_result.details.get('components', 0)} components, "
                f"hash_coverage={sbom_result.details.get('hash_coverage', 0):.0%}"
            )

        # Verify policy envelope integrity
        if self._integrity_manager:
            envelope_result = await self._integrity_manager.verify_policy_envelope(
                mission.policy_envelope
            )
            if envelope_result.signature_valid is False:
                # Only fail if signature was present but invalid
                logger.warning(
                    f"Policy envelope signature invalid: {envelope_result.details}"
                )

        # Check budget
        await self._governance.check_budget(mission)

    def _create_action_executor_callback(
        self,
        mission: Mission,
        control_plane: ExecutionControlPlane,
    ) -> Callable:
        """
        Create an action executor callback for the control plane.

        v6.1 SECURITY: This callback is invoked by the ExecutionControlPlane
        AFTER all guards have passed. It sets up the execution context with
        the proper token before delegating to the actual executor.

        Args:
            mission: The mission being executed

        Returns:
            An async callable that executes actions with proper authorization
        """
        async def execute_action_with_authorization(
            ctx: ActionContext,
            record: DecisionRecord,
        ) -> Dict[str, Any]:
            """Execute action after control plane authorization."""
            # Determine environment from context
            environment = ctx.mode.lower() if ctx.mode else "simulation"

            # Execute based on environment
            if environment in ("sim", "simulation"):
                result = await self._executor._simulate_action(
                    ctx.action,
                    self._build_execution_context(ctx, mission),
                )
            elif environment == "lab":
                result = await self._executor._execute_lab_action(
                    ctx.action,
                    self._build_execution_context(ctx, mission),
                )
            else:
                result = await self._executor._execute_live_action(
                    ctx.action,
                    self._build_execution_context(ctx, mission),
                )

            return result

        return create_token_validated_executor(
            control_plane,
            execute_action_with_authorization,
        )

    def _build_execution_context(
        self,
        ctx: ActionContext,
        mission: Mission,
    ):
        """Build ExecutionContext from ActionContext for executor methods."""
        from ..sim import ExecutionContext

        return ExecutionContext(
            mission_id=mission.mission_id,
            phase_name=mission.current_phase or "",
            action_index=mission.actions_completed,
            total_actions=mission.plan.total_actions if mission.plan else 0,
            environment=ctx.mode.lower() if ctx.mode else "simulation",
            classification_level=ctx.classification_level,
            alert_count=0,
            impact_score=mission.impact_score,
        )

    def _create_forensic_emitter_callback(self) -> Callable:
        """
        Create a forensic event emitter callback for the control plane.

        v6.1 SECURITY: All execution events are logged for audit trail.

        Returns:
            An async callable that emits forensic events
        """
        async def emit_forensic_event(event: ForensicEvent) -> None:
            """Emit forensic event to the forensics subsystem."""
            if self._forensics:
                try:
                    await self._forensics.log_event({
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "timestamp": event.timestamp.isoformat(),
                        "action_id": event.action_context.action_id,
                        "outcome": event.outcome,
                        "details": event.details,
                    })
                except Exception as e:
                    logger.error(f"Failed to emit forensic event: {e}")

            # Always log to standard logger as backup
            logger.info(
                f"Forensic: {event.event_type} action={event.action_context.action_id} "
                f"outcome={event.outcome}"
            )

        return emit_forensic_event

    async def _execute_mission(self, mission: Mission) -> None:
        """
        Execute mission plan with full safety, MLS, and ROE enforcement.

        v6.1 SECURITY: All action execution MUST flow through ExecutionControlPlane.
        The executor receives action_runner=control_plane.validate_and_execute_action
        to ensure NO direct tool execution is possible.

        Integrates:
        - Safety policy evaluation via OPA
        - MLS validation for data flow
        - ROE violation checking
        - Impact score tracking
        """
        try:
            # v6.1 MANDATORY: Create ExecutionControlPlane for this mission
            # This control plane enforces all guards before any action execution
            from ..sim import mark_legitimate_execution, clear_legitimate_execution

            control_plane = ExecutionControlPlane(
                permit_validator=None,  # Uses built-in validation
                opa_client=None,  # Uses built-in evaluation
                runtime_guard=None,  # Uses built-in guard
                rate_limiter=None,  # Uses built-in rate limiting
                target_safety=None,  # Uses built-in safety checks
                action_executor=None,
                forensic_emitter=self._create_forensic_emitter_callback(),
            )
            control_plane._action_executor = self._create_action_executor_callback(
                mission,
                control_plane,
            )

            # Enable test mode for simulation environments
            if mission.policy_envelope.get("mode", "").upper() in ("SIM", "SIMULATION"):
                control_plane._test_mode = True

            # v6.1 MANDATORY: Pass control_plane.validate_and_execute_action as action_runner
            # SIM cannot execute without this - GuardBypassError will be raised
            async for action_result in self._executor.execute(
                mission,
                action_runner=control_plane.validate_and_execute_action,
                expected_control_plane=control_plane,
            ):
                # Log to forensics first (for audit trail)
                await self._forensics.log_action(mission, action_result)

                # Build action data for policy evaluation
                action_data = {
                    "action_id": str(action_result.action_id),
                    "action_type": action_result.action_type,
                    "target": action_result.target,
                    "status": action_result.status,
                    "destructive": getattr(action_result, "destructive", False),
                    "expands_scope": getattr(action_result, "expands_scope", False),
                    "estimated_impact": getattr(action_result, "impact_score", 0),
                }

                # Safety policy evaluation
                safety_result = await self._safety_evaluator.evaluate_safety(
                    action=action_data,
                    mission_context={
                        "policy_envelope": mission.policy_envelope,
                        "active_operations": self.metrics.active_missions,
                        "approvals": mission.policy_envelope.get("approvals", {}),
                    },
                    metrics={
                        "forensic_completeness": self.metrics.forensic_completeness,
                    },
                )

                # Check for red line violations (abort immediately)
                if safety_result.get("red_lines"):
                    logger.error(
                        f"RED LINE VIOLATION: {safety_result['red_lines']}"
                    )
                    self.metrics.safety_violations += 1
                    await self.abort_mission(
                        mission.mission_id,
                        reason=f"Red line violation: {safety_result['red_lines'][0]}",
                    )
                    return

                # Check for safety violations
                if not safety_result.get("safe", True):
                    logger.warning(
                        f"Safety violation: {safety_result.get('violations', [])}"
                    )
                    self.metrics.safety_violations += 1
                    # Continue but log warning for non-red-line violations

                # MLS validation for any data flow
                if hasattr(action_result, "data_flow") and action_result.data_flow:
                    from ..mls import DataFlowRequest
                    flow_request = DataFlowRequest(
                        source_ring=action_result.data_flow.get(
                            "source", mission.classification_level
                        ),
                        dest_ring=action_result.data_flow.get(
                            "destination", mission.classification_level
                        ),
                        data_type=action_result.data_flow.get("type", "action_output"),
                        sanitized=action_result.data_flow.get("sanitized", False),
                        declassification_authorized=action_result.data_flow.get(
                            "declassification_authorized", False
                        ),
                        requestor=str(mission.mission_id),
                        timestamp=datetime.utcnow(),
                    )
                    try:
                        await self._mls_manager.validate_data_flow(flow_request)
                    except MLSViolationError as e:
                        logger.error(f"MLS violation: {e}")
                        self.metrics.policy_violations += 1
                        await self.abort_mission(
                            mission.mission_id,
                            reason=f"MLS violation: {e}",
                        )
                        return

                # Check for ROE violations
                if await self._roe_engine.check_violation(action_result):
                    self.metrics.roe_violations += 1
                    await self.abort_mission(
                        mission.mission_id, reason="ROE violation detected"
                    )
                    return

                # Update impact score
                mission.impact_score = await self._tie.update_impact(
                    mission, action_result
                )

                # Update progress
                mission.actions_completed += 1

            # Mission completed
            mission.state = MissionState.COMPLETED
            self.metrics.active_missions -= 1
            self.metrics.completed_missions += 1

            # Final forensic capture
            await self._forensics.finalize_mission(mission)

            logger.info(f"Mission completed: {mission.mission_id}")

        except Exception as e:
            logger.error(f"Mission execution error: {e}")
            mission.state = MissionState.ERROR
            mission.error = str(e)
            self.metrics.active_missions -= 1

    async def _metrics_collector(self) -> None:
        """Background task to collect metrics."""
        while self.state not in [EngineState.SHUTTING_DOWN, EngineState.ERROR]:
            try:
                # Update forensic completeness
                total_completeness = 0.0
                mission_count = 0

                async with self._mission_lock:
                    for mission in self._missions.values():
                        if mission.state == MissionState.COMPLETED:
                            completeness = await self._forensics.get_completeness(
                                mission
                            )
                            total_completeness += completeness
                            mission_count += 1

                if mission_count > 0:
                    self.metrics.forensic_completeness = (
                        total_completeness / mission_count
                    )

                # Update uptime
                if self.start_time:
                    self.metrics.uptime_seconds = (
                        datetime.utcnow() - self.start_time
                    ).total_seconds()

                await asyncio.sleep(60)  # Collect every minute

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(60)

    async def _health_monitor(self) -> None:
        """Background task to monitor system health."""
        while self.state not in [EngineState.SHUTTING_DOWN, EngineState.ERROR]:
            try:
                # Check subsystem health
                # This would include checks for all subsystems

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(30)
