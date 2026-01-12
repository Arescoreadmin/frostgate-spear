"""
Frost Gate Spear - ROE Engine

Rules of Engagement enforcement subsystem.
Validates and enforces ROE constraints on all operations.
Integrates with OPA for policy evaluation.

Gate M: OPA Bundle Signing
- Verifies bundle signature BEFORE loading policies
- FAIL CLOSED: If verification fails, policies MUST NOT load
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

import aiohttp

from ..core.config import Config
from ..core.exceptions import ROEViolationError
from ..policy.bundle_verify import (
    PolicyBundleVerificationError,
    PolicyBundleVerifier,
)

logger = logging.getLogger(__name__)


@dataclass
class OPAConfig:
    """OPA server configuration."""
    url: str = "http://localhost:8181"
    policy_path: str = "frostgate/roe"
    timeout: float = 5.0
    retry_count: int = 3
    retry_delay: float = 0.5


class OPAClient:
    """
    Open Policy Agent (OPA) client for policy evaluation.

    Provides:
    - Policy evaluation via OPA REST API
    - Caching for repeated queries
    - Fallback to local evaluation
    - Health checking
    """

    def __init__(self, config: OPAConfig):
        """Initialize OPA client."""
        self._config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._healthy = False
        self._cache: Dict[str, Dict] = {}
        self._cache_ttl = 60  # seconds

    async def start(self) -> None:
        """Start OPA client and verify connectivity."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._config.timeout)
        )
        await self._health_check()

    async def stop(self) -> None:
        """Stop OPA client."""
        if self._session:
            await self._session.close()
            self._session = None

    async def close(self) -> None:
        """Close the OPA client (alias for stop)."""
        await self.stop()

    async def _health_check(self) -> bool:
        """Check OPA server health."""
        if not self._session:
            return False

        try:
            async with self._session.get(f"{self._config.url}/health") as resp:
                self._healthy = resp.status == 200
                if self._healthy:
                    logger.info(f"OPA server healthy at {self._config.url}")
                return self._healthy
        except Exception as e:
            logger.warning(f"OPA health check failed: {e}")
            self._healthy = False
            return False

    async def evaluate(
        self,
        input_data: Dict[str, Any],
        policy_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate policy against input data.

        Args:
            input_data: Input data for policy evaluation
            policy_path: Optional override for policy path

        Returns:
            Policy evaluation result
        """
        path = policy_path or self._config.policy_path
        url = f"{self._config.url}/v1/data/{path.replace('.', '/')}"

        if not self._session or not self._healthy:
            logger.warning("OPA not available, using local evaluation fallback")
            return await self._local_evaluate(input_data)

        for attempt in range(self._config.retry_count):
            try:
                async with self._session.post(
                    url,
                    json={"input": input_data},
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        return result.get("result", {})
                    else:
                        error_text = await resp.text()
                        logger.warning(
                            f"OPA evaluation failed (status {resp.status}): {error_text}"
                        )

            except asyncio.TimeoutError:
                logger.warning(f"OPA evaluation timeout (attempt {attempt + 1})")
            except Exception as e:
                logger.warning(f"OPA evaluation error: {e}")

            if attempt < self._config.retry_count - 1:
                await asyncio.sleep(self._config.retry_delay)

        # Fallback to local evaluation
        return await self._local_evaluate(input_data)

    async def evaluate_roe(
        self,
        action: Dict[str, Any],
        roe: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate ROE policy for an action.

        Args:
            action: Action to evaluate
            roe: ROE configuration
            context: Additional context

        Returns:
            Evaluation result with allow/deny and violations
        """
        input_data = {
            "action": action,
            "roe": roe,
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        result = await self.evaluate(input_data, "frostgate/roe")

        return {
            "allowed": result.get("allow", False),
            "violations": result.get("violations", []),
            "risk_tier": result.get("risk_tier", 1),
        }

    async def _local_evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback local policy evaluation when OPA unavailable.

        Implements core ROE checks without full OPA policy.
        """
        violations = []
        action = input_data.get("action", {})
        roe = input_data.get("roe", {})

        # Check time window
        if roe.get("valid_from") and roe.get("valid_to"):
            now = datetime.utcnow()
            try:
                valid_from = datetime.fromisoformat(
                    roe["valid_from"].replace("Z", "+00:00")
                ).replace(tzinfo=None)
                valid_to = datetime.fromisoformat(
                    roe["valid_to"].replace("Z", "+00:00")
                ).replace(tzinfo=None)
                if now < valid_from or now > valid_to:
                    violations.append("Action outside authorized time window")
            except ValueError:
                pass

        # Check scope
        target = action.get("target", {})
        target_asset = target.get("asset", "")
        disallowed = roe.get("disallowed_assets", [])
        if target_asset in disallowed:
            violations.append(f"Target {target_asset} is explicitly disallowed")

        # Check tool permissions
        tool = action.get("tool")
        disallowed_tools = roe.get("disallowed_tools", [])
        if tool in disallowed_tools:
            violations.append(f"Tool {tool} is explicitly disallowed")

        # Check lateral movement
        if action.get("type") == "lateral_movement":
            if not roe.get("lateral_movement_authorized"):
                violations.append("Lateral movement not authorized")

        # Check destructive operations
        if action.get("destructive"):
            if not roe.get("destructive_ops_authorized"):
                violations.append("Destructive operations not authorized")

        return {
            "allow": len(violations) == 0,
            "violations": violations,
            "risk_tier": input_data.get("context", {}).get("risk_tier", 1),
        }

    @property
    def is_healthy(self) -> bool:
        """Check if OPA client is healthy."""
        return self._healthy


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

    Gate M: OPA Bundle Signing
    - Verifies policy bundle signature BEFORE loading
    - FAIL CLOSED: If verification fails, engine MUST NOT start
    """

    def __init__(self, config: Config):
        """Initialize ROE Engine."""
        self.config = config
        self._opa_client = None
        self._roe_cache: Dict[str, Dict] = {}
        self._violation_log: List[Dict] = []
        self._bundle_verified = False
        self._bundle_verification_result = None

    async def start(self) -> None:
        """
        Start the ROE Engine.

        Gate M: Verifies policy bundle BEFORE loading OPA.
        FAIL CLOSED: If verification fails, raises PolicyBundleVerificationError.
        """
        logger.info("Starting ROE Engine...")

        # Gate M: Verify OPA policy bundle before loading
        await self._verify_policy_bundle()

        # Initialize OPA client for policy evaluation
        await self._initialize_opa()
        logger.info("ROE Engine started")

    async def _verify_policy_bundle(self) -> None:
        """
        Gate M: Verify OPA policy bundle signature.

        FAIL CLOSED: If verification fails, the engine MUST NOT load policies.

        Raises:
            PolicyBundleVerificationError: If bundle verification fails.
        """
        # Check if bundle verification is enabled
        bundle_verification_enabled = getattr(
            self.config.policy, "bundle_verification_enabled", True
        )

        if not bundle_verification_enabled:
            logger.warning(
                "SECURITY WARNING: OPA bundle verification is DISABLED. "
                "This is only acceptable in development/test environments."
            )
            self._bundle_verified = False
            return

        # Resolve paths
        base_path = Path(self.config.base_path)
        trust_store_path = base_path / getattr(
            self.config.policy, "trust_store_path", "integrity/trust_store.json"
        )
        bundle_path = base_path / getattr(
            self.config.policy, "bundle_path", "build/opa_bundle.tar.gz"
        )
        sig_path = base_path / getattr(
            self.config.policy, "bundle_sig_path", "build/opa_bundle.tar.gz.sig"
        )
        manifest_path = base_path / getattr(
            self.config.policy, "bundle_manifest_path", "build/opa_bundle.manifest.json"
        )

        logger.info(f"Gate M: Verifying OPA policy bundle at {bundle_path}")

        try:
            verifier = PolicyBundleVerifier(
                trust_store_path=trust_store_path,
                bundle_dir=base_path / "build",
            )
            verifier.load_trust_store()

            result = verifier.verify_bundle(
                bundle_path=bundle_path,
                sig_path=sig_path,
                manifest_path=manifest_path,
            )

            self._bundle_verified = result.verified
            self._bundle_verification_result = result

            logger.info(
                f"Gate M: Bundle verified successfully - "
                f"hash={result.bundle_hash}, key={result.key_id}, "
                f"signed_at={result.signed_at}"
            )

        except PolicyBundleVerificationError as e:
            logger.error(f"Gate M FAILURE: Bundle verification failed - {e}")
            # FAIL CLOSED: Re-raise to prevent engine startup
            raise

    async def stop(self) -> None:
        """Stop the ROE Engine."""
        logger.info("Stopping ROE Engine...")
        if self._opa_client:
            await self._opa_client.close()

    async def _initialize_opa(self) -> None:
        """Initialize OPA policy agent for ROE enforcement."""
        # Get OPA configuration from config or use defaults
        opa_url = getattr(self.config, "opa_url", None)
        if opa_url is None:
            opa_url = getattr(self.config.roe, "opa_url", "http://localhost:8181")

        opa_config = OPAConfig(
            url=opa_url,
            policy_path="frostgate/roe",
            timeout=5.0,
            retry_count=3,
        )

        self._opa_client = OPAClient(opa_config)
        await self._opa_client.start()

        if self._opa_client.is_healthy:
            logger.info("OPA client initialized and connected")
        else:
            logger.warning(
                "OPA server not available - using local policy evaluation fallback"
            )

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
        Validate a single action against ROE using OPA.

        Args:
            action: Action to validate
            roe: ROE constraints
            context: Additional context (alert count, etc.)

        Returns:
            Validation result
        """
        violations = []

        # Use OPA for policy evaluation if available
        if self._opa_client:
            opa_result = await self._opa_client.evaluate_roe(action, roe, context)
            if not opa_result.get("allowed", False):
                violations.extend(opa_result.get("violations", []))
        else:
            # Fallback to local validation
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
