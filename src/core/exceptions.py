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
