"""
Frost Gate Spear Exception Hierarchy

Custom exceptions for error handling and policy enforcement.
"""

from typing import Any, Dict, List, Optional


class FrostGateError(Exception):
    """Base exception for all Frost Gate Spear errors."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or "FROSTGATE_ERROR"
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class PolicyViolationError(FrostGateError):
    """Raised when a policy constraint is violated."""

    def __init__(
        self,
        message: str,
        policy_id: Optional[str] = None,
        violations: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="POLICY_VIOLATION",
            details={
                "policy_id": policy_id,
                "violations": violations or [],
            },
        )
        self.policy_id = policy_id
        self.violations = violations or []


class ROEViolationError(FrostGateError):
    """Raised when Rules of Engagement are violated."""

    def __init__(
        self,
        message: str,
        roe_rule: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="ROE_VIOLATION",
            details={
                "roe_rule": roe_rule,
                "action": action,
                "target": target,
            },
        )
        self.roe_rule = roe_rule
        self.action = action
        self.target = target


class SafetyConstraintError(FrostGateError):
    """Raised when a safety constraint is violated."""

    def __init__(
        self,
        message: str,
        constraint: Optional[str] = None,
        current_value: Optional[Any] = None,
        threshold: Optional[Any] = None,
    ):
        super().__init__(
            message,
            code="SAFETY_CONSTRAINT_VIOLATION",
            details={
                "constraint": constraint,
                "current_value": current_value,
                "threshold": threshold,
            },
        )
        self.constraint = constraint
        self.current_value = current_value
        self.threshold = threshold


class MLSViolationError(FrostGateError):
    """Raised when Multi-Level Security constraints are violated."""

    def __init__(
        self,
        message: str,
        source_ring: Optional[str] = None,
        target_ring: Optional[str] = None,
        operation: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="MLS_VIOLATION",
            details={
                "source_ring": source_ring,
                "target_ring": target_ring,
                "operation": operation,
            },
        )
        self.source_ring = source_ring
        self.target_ring = target_ring
        self.operation = operation


class ApprovalRequiredError(FrostGateError):
    """Raised when required approvals are missing."""

    def __init__(
        self,
        message: str,
        required_roles: Optional[List[str]] = None,
        missing_roles: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="APPROVAL_REQUIRED",
            details={
                "required_roles": required_roles or [],
                "missing_roles": missing_roles or [],
            },
        )
        self.required_roles = required_roles or []
        self.missing_roles = missing_roles or []


class BudgetExceededError(FrostGateError):
    """Raised when budget limits are exceeded."""

    def __init__(
        self,
        message: str,
        budget_type: Optional[str] = None,
        current_usage: Optional[float] = None,
        limit: Optional[float] = None,
        is_soft_limit: bool = False,
    ):
        super().__init__(
            message,
            code="BUDGET_EXCEEDED",
            details={
                "budget_type": budget_type,
                "current_usage": current_usage,
                "limit": limit,
                "is_soft_limit": is_soft_limit,
            },
        )
        self.budget_type = budget_type
        self.current_usage = current_usage
        self.limit = limit
        self.is_soft_limit = is_soft_limit


class BlastRadiusExceededError(SafetyConstraintError):
    """Raised when estimated impact exceeds blast radius cap."""

    def __init__(
        self,
        message: str,
        estimated_impact: float,
        blast_radius_cap: float,
    ):
        super().__init__(
            message,
            constraint="blast_radius",
            current_value=estimated_impact,
            threshold=blast_radius_cap,
        )
        self.code = "BLAST_RADIUS_EXCEEDED"


class ForensicIntegrityError(FrostGateError):
    """Raised when forensic integrity is compromised."""

    def __init__(
        self,
        message: str,
        expected_hash: Optional[str] = None,
        actual_hash: Optional[str] = None,
        artifact: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="FORENSIC_INTEGRITY_ERROR",
            details={
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "artifact": artifact,
            },
        )
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        self.artifact = artifact


class PersonaConstraintError(FrostGateError):
    """Raised when persona violates constraints."""

    def __init__(
        self,
        message: str,
        persona_id: Optional[str] = None,
        constraint_type: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="PERSONA_CONSTRAINT_VIOLATION",
            details={
                "persona_id": persona_id,
                "constraint_type": constraint_type,
            },
        )
        self.persona_id = persona_id
        self.constraint_type = constraint_type


class SimulationValidationError(FrostGateError):
    """Raised when simulation validation fails."""

    def __init__(
        self,
        message: str,
        sim_runs: int = 0,
        required_runs: int = 1000,
        violations: int = 0,
    ):
        super().__init__(
            message,
            code="SIMULATION_VALIDATION_ERROR",
            details={
                "sim_runs": sim_runs,
                "required_runs": required_runs,
                "violations": violations,
            },
        )
        self.sim_runs = sim_runs
        self.required_runs = required_runs
        self.violations = violations


class PromotionGateError(FrostGateError):
    """Raised when promotion gate requirements are not met."""

    def __init__(
        self,
        message: str,
        gate_name: Optional[str] = None,
        failed_criteria: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="PROMOTION_GATE_FAILED",
            details={
                "gate_name": gate_name,
                "failed_criteria": failed_criteria or [],
            },
        )
        self.gate_name = gate_name
        self.failed_criteria = failed_criteria or []


class RedLineViolationError(FrostGateError):
    """
    Raised when an absolute red line is crossed.

    Red lines are non-negotiable safety boundaries.
    """

    def __init__(
        self,
        message: str,
        red_line: str,
        action: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="RED_LINE_VIOLATION",
            details={
                "red_line": red_line,
                "action": action,
                "severity": "CRITICAL",
            },
        )
        self.red_line = red_line
        self.action = action


class PersonaValidationError(FrostGateError):
    """Raised when persona validation fails."""

    def __init__(
        self,
        message: str,
        persona_id: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="PERSONA_VALIDATION_ERROR",
            details={
                "persona_id": persona_id,
                "validation_errors": validation_errors or [],
            },
        )
        self.persona_id = persona_id
        self.validation_errors = validation_errors or []


class PersonaConstraintViolationError(FrostGateError):
    """
    Raised when a persona attempts to override immutable constraints.

    This is a CRITICAL security violation - personas CANNOT override
    ROE, safety, or policy constraints.
    """

    def __init__(
        self,
        message: str,
        constraint: str,
        attempted_value: Any,
        required_value: Any,
    ):
        super().__init__(
            message,
            code="PERSONA_CONSTRAINT_VIOLATION",
            details={
                "constraint": constraint,
                "attempted_value": attempted_value,
                "required_value": required_value,
                "severity": "CRITICAL",
            },
        )
        self.constraint = constraint
        self.attempted_value = attempted_value
        self.required_value = required_value


class PersonaSignatureError(FrostGateError):
    """Raised when persona signature validation fails."""

    def __init__(
        self,
        message: str,
        persona_id: Optional[str] = None,
        signer_id: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="PERSONA_SIGNATURE_ERROR",
            details={
                "persona_id": persona_id,
                "signer_id": signer_id,
            },
        )
        self.persona_id = persona_id
        self.signer_id = signer_id


class PersonaClassificationError(FrostGateError):
    """Raised when persona classification requirements are not met."""

    def __init__(
        self,
        message: str,
        persona_id: Optional[str] = None,
        required_ring: Optional[str] = None,
        current_ring: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="PERSONA_CLASSIFICATION_ERROR",
            details={
                "persona_id": persona_id,
                "required_ring": required_ring,
                "current_ring": current_ring,
            },
        )
        self.persona_id = persona_id
        self.required_ring = required_ring
        self.current_ring = current_ring


class CrossRingContaminationError(MLSViolationError):
    """Raised when cross-ring data contamination is detected."""

    def __init__(
        self,
        message: str,
        source_ring: str,
        target_ring: str,
        data_type: Optional[str] = None,
    ):
        super().__init__(
            message,
            source_ring=source_ring,
            target_ring=target_ring,
            operation="cross_ring_transfer",
        )
        self.code = "CROSS_RING_CONTAMINATION"
        self.data_type = data_type


class SBOMValidationError(FrostGateError):
    """Raised when SBOM validation fails."""

    def __init__(
        self,
        message: str,
        artifact_id: Optional[str] = None,
        missing_components: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="SBOM_VALIDATION_ERROR",
            details={
                "artifact_id": artifact_id,
                "missing_components": missing_components or [],
            },
        )
        self.artifact_id = artifact_id
        self.missing_components = missing_components or []


class ProvenanceValidationError(FrostGateError):
    """Raised when SLSA provenance validation fails."""

    def __init__(
        self,
        message: str,
        artifact_id: Optional[str] = None,
        slsa_level: Optional[int] = None,
        required_level: int = 3,
    ):
        super().__init__(
            message,
            code="PROVENANCE_VALIDATION_ERROR",
            details={
                "artifact_id": artifact_id,
                "slsa_level": slsa_level,
                "required_level": required_level,
            },
        )
        self.artifact_id = artifact_id
        self.slsa_level = slsa_level
        self.required_level = required_level


# ============================================================================
# Execution Control Plane Errors (v6.1 - Gate F Enforcement)
# ============================================================================


class PermitDeniedError(FrostGateError):
    """
    Raised when permit validation fails.

    The action cannot proceed because the permit is invalid, missing,
    or does not authorize the requested action.
    """

    def __init__(
        self,
        message: str,
        permit_id: Optional[str] = None,
        reason: Optional[str] = None,
        issues: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(
            message,
            code="PERMIT.DENIED",
            details={
                "permit_id": permit_id,
                "reason": reason,
                "issues": issues or [],
            },
        )
        self.permit_id = permit_id
        self.reason = reason
        self.issues = issues or []


class PermitExpiredError(FrostGateError):
    """
    Raised when permit TTL has expired.

    This can occur at preflight OR mid-execution when TTL expires
    between actions. Execution MUST halt immediately.
    """

    def __init__(
        self,
        message: str,
        permit_id: Optional[str] = None,
        expired_at: Optional[str] = None,
        action_id: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="PERMIT.EXPIRED",
            details={
                "permit_id": permit_id,
                "expired_at": expired_at,
                "action_id": action_id,
            },
        )
        self.permit_id = permit_id
        self.expired_at = expired_at
        self.action_id = action_id


class PolicyDeniedError(FrostGateError):
    """
    Raised when OPA policy evaluation denies the action.

    Includes ABAC policy violations.
    """

    def __init__(
        self,
        message: str,
        policy_path: Optional[str] = None,
        decision: Optional[str] = None,
        violations: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="POLICY.DENIED",
            details={
                "policy_path": policy_path,
                "decision": decision,
                "violations": violations or [],
            },
        )
        self.policy_path = policy_path
        self.decision = decision
        self.violations = violations or []


class ScopeDriftError(FrostGateError):
    """
    Raised when scope drift exceeds P2+ threshold.

    P2+ drift MUST halt execution and revoke permit.
    """

    def __init__(
        self,
        message: str,
        drift_score: float,
        severity: str,
        out_of_scope_actions: Optional[List[str]] = None,
    ):
        super().__init__(
            message,
            code="RUNTIME.SCOPE.DRIFT",
            details={
                "drift_score": drift_score,
                "severity": severity,
                "out_of_scope_actions": out_of_scope_actions or [],
                "action_required": "HALT_AND_REVOKE",
            },
        )
        self.drift_score = drift_score
        self.severity = severity
        self.out_of_scope_actions = out_of_scope_actions or []


class StepUpRequiredError(FrostGateError):
    """
    Raised when step-up authentication is required.

    The action cannot proceed without additional authentication
    (hardware token, biometric, dual approval).
    """

    def __init__(
        self,
        message: str,
        action_id: Optional[str] = None,
        required_method: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="ABAC.STEPUP.REQUIRED",
            details={
                "action_id": action_id,
                "required_method": required_method,
                "reason": reason,
            },
        )
        self.action_id = action_id
        self.required_method = required_method
        self.reason = reason


class RateLimitedError(FrostGateError):
    """
    Raised when rate limit is exceeded.

    Execution MUST block until rate limit resets.
    """

    def __init__(
        self,
        message: str,
        target_id: Optional[str] = None,
        current_rate: int = 0,
        max_rate: int = 0,
        window_seconds: int = 60,
    ):
        super().__init__(
            message,
            code="RUNTIME.RATE.EXCEEDED",
            details={
                "target_id": target_id,
                "current_rate": current_rate,
                "max_rate": max_rate,
                "window_seconds": window_seconds,
            },
        )
        self.target_id = target_id
        self.current_rate = current_rate
        self.max_rate = max_rate
        self.window_seconds = window_seconds


class TargetUnsafeError(FrostGateError):
    """
    Raised when target safety envelope is violated.

    This includes health probe failures, stop conditions,
    and fingerprint mismatches.
    """

    def __init__(
        self,
        message: str,
        target_id: Optional[str] = None,
        stop_condition: Optional[str] = None,
        health_state: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="TARGET.UNSAFE",
            details={
                "target_id": target_id,
                "stop_condition": stop_condition,
                "health_state": health_state,
            },
        )
        self.target_id = target_id
        self.stop_condition = stop_condition
        self.health_state = health_state


class WitnessRequiredError(FrostGateError):
    """
    Raised when dual attestation requires witness but none is available.

    For modes requiring dual attestation (CANARY, SHADOW, LIVE_*),
    execution MUST halt if witness is unavailable.
    """

    def __init__(
        self,
        message: str,
        action_id: Optional[str] = None,
        mode: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="RUNTIME.WITNESS.REQUIRED",
            details={
                "action_id": action_id,
                "mode": mode,
            },
        )
        self.action_id = action_id
        self.mode = mode


class GuardBypassError(FrostGateError):
    """
    CRITICAL: Raised when execution bypasses the guard chain.

    This is a SECURITY FAILURE. If an action executes without
    passing through validate_and_execute_action(), this error
    MUST be raised and the action MUST NOT execute.

    Any detection of bypass paths in CI MUST fail the build.
    """

    def __init__(
        self,
        message: str,
        bypass_path: Optional[str] = None,
        caller: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="STRUCTURAL.NO_BYPASS.VIOLATION",
            details={
                "bypass_path": bypass_path,
                "caller": caller,
                "severity": "CRITICAL",
            },
        )
        self.bypass_path = bypass_path
        self.caller = caller


class SoDViolationError(FrostGateError):
    """
    Raised when Separation of Duties is violated.

    Executor MUST NOT be an approver for risk tier 2+ in LIVE modes.
    """

    def __init__(
        self,
        message: str,
        executor_id: Optional[str] = None,
        conflicting_role: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="ABAC.SOD.VIOLATION",
            details={
                "executor_id": executor_id,
                "conflicting_role": conflicting_role,
            },
        )
        self.executor_id = executor_id
        self.conflicting_role = conflicting_role


class DecisionRecordMissingError(FrostGateError):
    """
    Raised when an action attempts to execute without a DecisionRecord.

    If DecisionRecord does not exist, execution is considered INVALID.
    """

    def __init__(
        self,
        message: str,
        action_id: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="EXECUTION.DECISION_RECORD.MISSING",
            details={
                "action_id": action_id,
            },
        )
        self.action_id = action_id
