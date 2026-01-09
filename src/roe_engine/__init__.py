"""
Frost Gate Spear - ROE Engine

Rules of Engagement enforcement subsystem.
Validates and enforces ROE constraints on all operations.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.config import Config
from ..core.exceptions import ROEViolationError

logger = logging.getLogger(__name__)


@dataclass
class ROEValidationResult:
    """Result of ROE validation."""
    valid: bool
    violations: List[str]
    timestamp: datetime
    roe_hash: str


class ROEEngine:
    """
    Rules of Engagement Engine.

    Enforces ROE constraints including:
    - Allowed/disallowed assets
    - Tool permissions
    - Time windows
    - Alert footprint caps
    - Blast radius limits
    - Lateral movement authorization
    """

    def __init__(self, config: Config):
        """Initialize ROE Engine."""
        self.config = config
        self._opa_client = None
        self._roe_cache: Dict[str, Dict] = {}
        self._violation_log: List[Dict] = []

    async def start(self) -> None:
        """Start the ROE Engine."""
        logger.info("Starting ROE Engine...")
        # Initialize OPA client for policy evaluation
        await self._initialize_opa()
        logger.info("ROE Engine started")

    async def stop(self) -> None:
        """Stop the ROE Engine."""
        logger.info("Stopping ROE Engine...")
        if self._opa_client:
            await self._opa_client.close()

    async def _initialize_opa(self) -> None:
        """Initialize OPA policy agent."""
        # In production, this would connect to OPA
        pass

    async def validate_roe(self, roe: Dict[str, Any]) -> ROEValidationResult:
        """
        Validate ROE definition.

        Args:
            roe: ROE configuration dictionary

        Returns:
            Validation result

        Raises:
            ROEViolationError: If ROE is invalid
        """
        violations = []

        # Required fields
        required_fields = ["allowed_assets", "allowed_networks"]
        for field in required_fields:
            if field not in roe:
                violations.append(f"Missing required field: {field}")

        # Validate blast radius cap
        if "blast_radius_cap" in roe:
            if not 0 <= roe["blast_radius_cap"] <= 100:
                violations.append("blast_radius_cap must be between 0 and 100")

        # Validate time window
        if "valid_from" in roe and "valid_to" in roe:
            try:
                valid_from = datetime.fromisoformat(roe["valid_from"].replace("Z", "+00:00"))
                valid_to = datetime.fromisoformat(roe["valid_to"].replace("Z", "+00:00"))
                if valid_from >= valid_to:
                    violations.append("valid_from must be before valid_to")
            except ValueError as e:
                violations.append(f"Invalid datetime format: {e}")

        # Validate lateral movement config
        if roe.get("lateral_movement_authorized"):
            if not roe.get("lateral_movement_targets"):
                violations.append(
                    "lateral_movement_targets required when lateral_movement_authorized"
                )

        result = ROEValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            timestamp=datetime.utcnow(),
            roe_hash=self._compute_roe_hash(roe),
        )

        if not result.valid:
            raise ROEViolationError(
                f"ROE validation failed: {violations}",
                violations=violations,
            )

        return result

    async def validate_plan(
        self, plan: Any, policy_envelope: Dict[str, Any]
    ) -> ROEValidationResult:
        """
        Validate execution plan against ROE.

        Args:
            plan: Execution plan to validate
            policy_envelope: Policy envelope with ROE constraints

        Returns:
            Validation result
        """
        violations = []
        roe = policy_envelope.get("roe", {})

        # Validate each action in plan
        for phase in plan.phases:
            for action in phase.get("actions", []):
                action_violations = await self._validate_action(action, roe)
                violations.extend(action_violations)

        return ROEValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            timestamp=datetime.utcnow(),
            roe_hash=self._compute_roe_hash(roe),
        )

    async def validate_action(
        self,
        action: Dict[str, Any],
        roe: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ROEValidationResult:
        """
        Validate a single action against ROE.

        Args:
            action: Action to validate
            roe: ROE constraints
            context: Additional context (alert count, etc.)

        Returns:
            Validation result
        """
        violations = await self._validate_action(action, roe, context)

        if violations:
            self._log_violation(action, violations)

        return ROEValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            timestamp=datetime.utcnow(),
            roe_hash=self._compute_roe_hash(roe),
        )

    async def check_violation(self, action_result: Any) -> bool:
        """
        Check if action result indicates ROE violation.

        Args:
            action_result: Result from executed action

        Returns:
            True if violation detected
        """
        # Check for scope expansion
        if getattr(action_result, "scope_expanded", False):
            return True

        # Check for unauthorized lateral movement
        if action_result.action_type == "lateral_movement":
            if not getattr(action_result, "authorized", False):
                return True

        return False

    async def _validate_action(
        self,
        action: Dict[str, Any],
        roe: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Validate single action against ROE constraints."""
        violations = []
        context = context or {}

        # Check target is in scope
        target = action.get("target", {})
        target_asset = target.get("asset", "")

        allowed_assets = roe.get("allowed_assets", [])
        disallowed_assets = roe.get("disallowed_assets", [])

        if disallowed_assets and target_asset in disallowed_assets:
            violations.append(f"Target {target_asset} is explicitly disallowed")

        if allowed_assets and target_asset not in allowed_assets:
            # Check network scope
            if not self._target_in_allowed_networks(target, roe):
                violations.append(f"Target {target_asset} is outside allowed scope")

        # Check tool is permitted
        tool = action.get("tool")
        allowed_tools = roe.get("allowed_tools", [])
        disallowed_tools = roe.get("disallowed_tools", [])

        if disallowed_tools and tool in disallowed_tools:
            violations.append(f"Tool {tool} is explicitly disallowed")

        if allowed_tools and tool not in allowed_tools:
            # Check tool category
            allowed_categories = roe.get("allowed_tool_categories", [])
            tool_category = self._get_tool_category(tool)
            if tool_category not in allowed_categories:
                violations.append(f"Tool {tool} is not in allowed list or categories")

        # Check time window
        if roe.get("time_restrictions"):
            if not self._within_time_window(roe):
                violations.append("Action attempted outside authorized time window")

        # Check alert footprint
        alert_cap = roe.get("alert_footprint_cap")
        current_alerts = context.get("current_alert_count", 0)
        if alert_cap and current_alerts >= alert_cap:
            violations.append(
                f"Alert footprint cap exceeded: {current_alerts} >= {alert_cap}"
            )

        # Check lateral movement authorization
        if action.get("type") == "lateral_movement":
            if not roe.get("lateral_movement_authorized"):
                violations.append("Lateral movement not authorized in ROE")
            else:
                allowed_targets = roe.get("lateral_movement_targets", [])
                if allowed_targets and target_asset not in allowed_targets:
                    violations.append(
                        f"Target {target_asset} not in lateral movement targets"
                    )

        # Check destructive operations
        if action.get("destructive"):
            if not roe.get("destructive_ops_authorized"):
                violations.append("Destructive operations not authorized")

        return violations

    def _target_in_allowed_networks(
        self, target: Dict[str, Any], roe: Dict[str, Any]
    ) -> bool:
        """Check if target is in allowed networks."""
        allowed_networks = roe.get("allowed_networks", [])
        target_network = target.get("network", "")

        for network in allowed_networks:
            if self._network_contains(network, target_network):
                return True
        return False

    def _network_contains(self, cidr: str, target: str) -> bool:
        """Check if CIDR contains target network."""
        # Simplified check - in production use ipaddress module
        return cidr == target or target.startswith(cidr.split("/")[0])

    def _get_tool_category(self, tool: str) -> str:
        """Get category for a tool."""
        tool_categories = {
            "nmap": "reconnaissance",
            "masscan": "reconnaissance",
            "shodan": "reconnaissance",
            "nikto": "vulnerability_scan",
            "nessus": "vulnerability_scan",
            "openvas": "vulnerability_scan",
            "metasploit": "exploitation",
            "cobalt_strike": "exploitation",
            "mimikatz": "credential_access",
            "bloodhound": "discovery",
            "impacket": "lateral_movement",
            "psexec": "lateral_movement",
        }
        return tool_categories.get(tool, "unknown")

    def _within_time_window(self, roe: Dict[str, Any]) -> bool:
        """Check if current time is within ROE time window."""
        now = datetime.utcnow()

        valid_from = roe.get("valid_from")
        valid_to = roe.get("valid_to")

        if valid_from:
            from_dt = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
            if now < from_dt.replace(tzinfo=None):
                return False

        if valid_to:
            to_dt = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))
            if now > to_dt.replace(tzinfo=None):
                return False

        return True

    def _compute_roe_hash(self, roe: Dict[str, Any]) -> str:
        """Compute hash of ROE for integrity verification."""
        import hashlib
        import json

        roe_str = json.dumps(roe, sort_keys=True)
        return f"sha256:{hashlib.sha256(roe_str.encode()).hexdigest()}"

    def _log_violation(self, action: Dict[str, Any], violations: List[str]) -> None:
        """Log ROE violation for audit."""
        self._violation_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "violations": violations,
        })
        logger.warning(f"ROE Violation: {violations}")

    def get_violation_log(self) -> List[Dict]:
        """Get violation log for audit."""
        return self._violation_log.copy()
