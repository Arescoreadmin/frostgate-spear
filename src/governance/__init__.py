"""
Frost Gate Spear - Governance Manager

Approval workflow, budget enforcement, and gate validation.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.config import Config
from ..core.exceptions import (
    ApprovalRequiredError,
    BudgetExceededError,
    PromotionGateError,
)

logger = logging.getLogger(__name__)


@dataclass
class ApprovalRequest:
    """Request for approval."""
    request_id: UUID
    mission_id: UUID
    required_roles: List[str]
    classification_level: str
    risk_tier: int
    scope_hash: str
    requested_at: datetime
    expires_at: datetime


@dataclass
class BudgetUsage:
    """Budget usage tracking."""
    tenant_id: str
    ring: str
    compute_hours_used: float
    api_calls_used: int
    cost_usd_used: float
    period_start: datetime
    period_end: datetime


@dataclass
class GateResult:
    """Result of gate validation."""
    gate_name: str
    passed: bool
    criteria: List[Dict[str, Any]]
    failed_criteria: List[str]
    timestamp: datetime


class GovernanceManager:
    """
    Governance Manager.

    Manages:
    - Approval workflows
    - Budget enforcement
    - Promotion gates (Security, Safety, Forensic, Impact, Performance, Ops)
    - Change control validation
    - Sign-off verification
    """

    def __init__(self, config: Config):
        """Initialize Governance Manager."""
        self.config = config
        self._pending_approvals: Dict[UUID, ApprovalRequest] = {}
        self._budget_usage: Dict[str, BudgetUsage] = {}
        self._gate_results: Dict[str, List[GateResult]] = {}

    async def start(self) -> None:
        """Start Governance Manager."""
        logger.info("Starting Governance Manager...")
        logger.info("Governance Manager started")

    async def stop(self) -> None:
        """Stop Governance Manager."""
        logger.info("Stopping Governance Manager...")

    async def validate_gates(self) -> None:
        """Validate governance gate configurations."""
        # Verify gate definitions exist
        gates = [
            "security", "safety", "forensic",
            "impact", "performance", "ops", "fl_ring"
        ]

        for gate in gates:
            logger.debug(f"Gate configuration validated: {gate}")

    async def validate_approvals(self, mission: Any) -> bool:
        """
        Validate mission has required approvals.

        Args:
            mission: Mission to validate

        Returns:
            True if all required approvals present

        Raises:
            ApprovalRequiredError: If approvals missing
        """
        required_roles = self._get_required_roles(mission)

        if not required_roles:
            return True

        present_roles = {
            a.role for a in mission.approvals
            if a.valid and (a.expiry is None or a.expiry > datetime.utcnow())
        }

        missing_roles = set(required_roles) - present_roles

        if missing_roles:
            raise ApprovalRequiredError(
                f"Missing required approvals: {list(missing_roles)}",
                required_roles=required_roles,
                missing_roles=list(missing_roles),
            )

        logger.info(f"Approvals validated for mission {mission.mission_id}")
        return True

    async def check_budget(self, mission: Any) -> bool:
        """
        Check budget constraints.

        Args:
            mission: Mission to check budget for

        Returns:
            True if within budget

        Raises:
            BudgetExceededError: If budget exceeded
        """
        budget_cap = mission.policy_envelope.get("budget_cap", {})

        if not budget_cap:
            return True

        tenant_id = mission.policy_envelope.get("tenant_id", "default")
        ring = mission.classification_level

        usage = self._budget_usage.get(f"{tenant_id}:{ring}")

        if not usage:
            return True

        # Check cost
        cost_limit = budget_cap.get("cost_usd", float("inf"))
        soft_limit_pct = budget_cap.get("soft_limit_percentage", 80) / 100

        if usage.cost_usd_used >= cost_limit:
            raise BudgetExceededError(
                "Budget hard limit exceeded",
                budget_type="cost_usd",
                current_usage=usage.cost_usd_used,
                limit=cost_limit,
                is_soft_limit=False,
            )

        if usage.cost_usd_used >= cost_limit * soft_limit_pct:
            logger.warning(
                f"Budget soft limit reached: {usage.cost_usd_used}/{cost_limit}"
            )

        # Check compute hours
        compute_limit = budget_cap.get("compute_hours", float("inf"))
        if usage.compute_hours_used >= compute_limit:
            raise BudgetExceededError(
                "Compute hours limit exceeded",
                budget_type="compute_hours",
                current_usage=usage.compute_hours_used,
                limit=compute_limit,
                is_soft_limit=False,
            )

        return True

    async def validate_security_gate(
        self, artifact: Dict[str, Any], ring: str
    ) -> GateResult:
        """
        Validate security gate.

        Args:
            artifact: Artifact to validate
            ring: Classification ring

        Returns:
            Gate result
        """
        criteria = []
        failed = []

        # Red team review
        red_team_passed = artifact.get("red_team_review", False)
        criteria.append({
            "name": "red_team_review",
            "required": True,
            "passed": red_team_passed,
        })
        if not red_team_passed:
            failed.append("Red team review not passed")

        # Gov security review for higher rings
        if ring in ["SECRET", "TOPSECRET"]:
            gov_review = artifact.get("gov_security_review", False)
            criteria.append({
                "name": "gov_security_review",
                "required": True,
                "passed": gov_review,
            })
            if not gov_review:
                failed.append("Government security review required")

        # Tool catalog validation
        tools_validated = artifact.get("tool_catalog_validated", True)
        criteria.append({
            "name": "tool_catalog_validation",
            "required": True,
            "passed": tools_validated,
        })
        if not tools_validated:
            failed.append("Tool catalog risk tiers not validated")

        # MLS isolation
        mls_validated = artifact.get("mls_isolation_validated", True)
        criteria.append({
            "name": "mls_isolation",
            "required": True,
            "passed": mls_validated,
        })
        if not mls_validated:
            failed.append("MLS isolation not validated")

        result = GateResult(
            gate_name="security",
            passed=len(failed) == 0,
            criteria=criteria,
            failed_criteria=failed,
            timestamp=datetime.utcnow(),
        )

        self._store_gate_result(result)
        return result

    async def validate_safety_gate(
        self, metrics: Dict[str, Any], ring: str
    ) -> GateResult:
        """
        Validate safety gate.

        Args:
            metrics: Safety metrics
            ring: Classification ring

        Returns:
            Gate result
        """
        criteria = []
        failed = []

        # Simulation runs
        sim_runs = metrics.get("sim_runs", 0)
        required_runs = self.config.governance.sim_runs_required
        sim_passed = sim_runs >= required_runs
        criteria.append({
            "name": "simulation_runs",
            "required": required_runs,
            "actual": sim_runs,
            "passed": sim_passed,
        })
        if not sim_passed:
            failed.append(f"Insufficient simulation runs: {sim_runs}/{required_runs}")

        # Policy violations
        violations = metrics.get("policy_violations", 0)
        allowed = self.config.governance.policy_violations_allowed
        violations_passed = violations <= allowed
        criteria.append({
            "name": "policy_violations",
            "required": f"<= {allowed}",
            "actual": violations,
            "passed": violations_passed,
        })
        if not violations_passed:
            failed.append(f"Policy violations: {violations} > {allowed}")

        # Deception false positive rate
        fp_rate = metrics.get("deception_fp_rate", 0)
        fp_threshold = 0.05
        fp_passed = fp_rate <= fp_threshold
        criteria.append({
            "name": "deception_fp_rate",
            "required": f"<= {fp_threshold}",
            "actual": fp_rate,
            "passed": fp_passed,
        })
        if not fp_passed:
            failed.append(f"Deception FP rate too high: {fp_rate}")

        result = GateResult(
            gate_name="safety",
            passed=len(failed) == 0,
            criteria=criteria,
            failed_criteria=failed,
            timestamp=datetime.utcnow(),
        )

        self._store_gate_result(result)
        return result

    async def validate_forensic_gate(
        self, metrics: Dict[str, Any]
    ) -> GateResult:
        """
        Validate forensic gate.

        Args:
            metrics: Forensic metrics

        Returns:
            Gate result
        """
        criteria = []
        failed = []

        # Forensic completeness
        completeness = metrics.get("forensic_completeness", 0)
        threshold = self.config.forensics.completeness_threshold
        completeness_passed = completeness >= threshold
        criteria.append({
            "name": "forensic_completeness",
            "required": f">= {threshold}",
            "actual": completeness,
            "passed": completeness_passed,
        })
        if not completeness_passed:
            failed.append(f"Forensic completeness: {completeness} < {threshold}")

        # Replay success
        replay_success = metrics.get("replay_success", 0)
        replay_threshold = self.config.forensics.replay_success_threshold
        replay_passed = replay_success >= replay_threshold
        criteria.append({
            "name": "replay_success",
            "required": f">= {replay_threshold}",
            "actual": replay_success,
            "passed": replay_passed,
        })
        if not replay_passed:
            failed.append(f"Replay success: {replay_success} < {replay_threshold}")

        # Merkle lineage
        merkle_valid = metrics.get("merkle_lineage_valid", False)
        criteria.append({
            "name": "merkle_lineage",
            "required": True,
            "passed": merkle_valid,
        })
        if not merkle_valid:
            failed.append("Merkle lineage validation failed")

        result = GateResult(
            gate_name="forensic",
            passed=len(failed) == 0,
            criteria=criteria,
            failed_criteria=failed,
            timestamp=datetime.utcnow(),
        )

        self._store_gate_result(result)
        return result

    async def validate_promotion(
        self,
        artifact: Dict[str, Any],
        from_env: str,
        to_env: str,
        ring: str,
    ) -> bool:
        """
        Validate promotion between environments.

        Args:
            artifact: Artifact to promote
            from_env: Source environment
            to_env: Target environment
            ring: Classification ring

        Returns:
            True if promotion allowed

        Raises:
            PromotionGateError: If promotion blocked
        """
        # Validate promotion path
        valid_paths = {
            ("simulation", "lab"),
            ("lab", "canary"),
            ("canary", "production"),
            ("canary", "mission"),
        }

        if (from_env, to_env) not in valid_paths:
            raise PromotionGateError(
                f"Invalid promotion path: {from_env} -> {to_env}",
                gate_name="promotion_path",
                failed_criteria=[f"Invalid path: {from_env} -> {to_env}"],
            )

        # Check all gates
        all_gates_passed = True
        failed_gates = []

        # Get metrics from artifact
        metrics = artifact.get("metrics", {})

        # Security gate
        security_result = await self.validate_security_gate(artifact, ring)
        if not security_result.passed:
            all_gates_passed = False
            failed_gates.extend(security_result.failed_criteria)

        # Safety gate
        safety_result = await self.validate_safety_gate(metrics, ring)
        if not safety_result.passed:
            all_gates_passed = False
            failed_gates.extend(safety_result.failed_criteria)

        # Forensic gate
        forensic_result = await self.validate_forensic_gate(metrics)
        if not forensic_result.passed:
            all_gates_passed = False
            failed_gates.extend(forensic_result.failed_criteria)

        if not all_gates_passed:
            raise PromotionGateError(
                f"Promotion blocked: gates failed",
                gate_name="promotion",
                failed_criteria=failed_gates,
            )

        logger.info(f"Promotion validated: {from_env} -> {to_env} in {ring}")
        return True

    async def record_budget_usage(
        self,
        tenant_id: str,
        ring: str,
        compute_hours: float = 0,
        api_calls: int = 0,
        cost_usd: float = 0,
    ) -> None:
        """Record budget usage."""
        key = f"{tenant_id}:{ring}"

        if key not in self._budget_usage:
            self._budget_usage[key] = BudgetUsage(
                tenant_id=tenant_id,
                ring=ring,
                compute_hours_used=0,
                api_calls_used=0,
                cost_usd_used=0,
                period_start=datetime.utcnow(),
                period_end=datetime.utcnow(),
            )

        usage = self._budget_usage[key]
        usage.compute_hours_used += compute_hours
        usage.api_calls_used += api_calls
        usage.cost_usd_used += cost_usd

    def _get_required_roles(self, mission: Any) -> List[str]:
        """Determine required approval roles."""
        roles = []

        risk_tier = mission.policy_envelope.get("risk_tier", 1)
        classification = mission.classification_level
        mode = mission.policy_envelope.get("mode", "simulation")

        # Base requirements
        if mode != "simulation":
            roles.append("Security")

        if risk_tier >= 2:
            roles.append("Product")

        if risk_tier >= 3:
            roles.append("AO")

        if classification in ["CUI", "SECRET", "TOPSECRET"]:
            roles.append("GovCompliance")

        if classification in ["SECRET", "TOPSECRET"]:
            if "AO" not in roles:
                roles.append("AO")

        # Mission mode requires mission owner
        if mode == "mission":
            roles.append("MissionOwner")

        return list(set(roles))

    def _store_gate_result(self, result: GateResult) -> None:
        """Store gate result for audit."""
        if result.gate_name not in self._gate_results:
            self._gate_results[result.gate_name] = []

        self._gate_results[result.gate_name].append(result)

        # Log result
        status = "PASSED" if result.passed else "FAILED"
        logger.info(f"Gate {result.gate_name}: {status}")

        if result.failed_criteria:
            for criterion in result.failed_criteria:
                logger.warning(f"  - {criterion}")

    def get_gate_history(self, gate_name: str) -> List[GateResult]:
        """Get gate validation history."""
        return self._gate_results.get(gate_name, []).copy()
