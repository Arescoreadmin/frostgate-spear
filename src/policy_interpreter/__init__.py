"""
Frost Gate Spear - Policy Interpreter

Policy envelope validation and interpretation subsystem.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema

from ..core.config import Config
from ..core.exceptions import PolicyViolationError

logger = logging.getLogger(__name__)


@dataclass
class PolicyValidationResult:
    """Result of policy validation."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    envelope_hash: str
    timestamp: datetime


class PolicyInterpreter:
    """
    Policy Interpreter.

    Validates and interprets policy envelopes including:
    - Schema validation
    - Approval verification
    - Budget constraints
    - Classification requirements
    - Scope verification
    """

    def __init__(self, config: Config):
        """Initialize Policy Interpreter."""
        self.config = config
        self._schema: Optional[Dict] = None
        self._policy_cache: Dict[str, Dict] = {}

    async def start(self) -> None:
        """Start the Policy Interpreter."""
        logger.info("Starting Policy Interpreter...")
        await self._load_schema()
        logger.info("Policy Interpreter started")

    async def stop(self) -> None:
        """Stop the Policy Interpreter."""
        logger.info("Stopping Policy Interpreter...")

    async def _load_schema(self) -> None:
        """Load policy envelope JSON schema."""
        schema_path = Path(self.config.base_path) / self.config.policy.envelope_schema_path

        if schema_path.exists():
            with open(schema_path) as f:
                self._schema = json.load(f)
            logger.info(f"Loaded policy schema from {schema_path}")
        else:
            logger.warning(f"Policy schema not found at {schema_path}")
            self._schema = {}

    async def validate_policies(self) -> None:
        """Validate that required policy files exist."""
        base = Path(self.config.base_path)

        required_files = [
            self.config.policy.roe_policy_path,
            self.config.policy.safety_policy_path,
            self.config.policy.mls_policy_path,
        ]

        missing = []
        for path in required_files:
            if not (base / path).exists():
                missing.append(path)

        if missing:
            raise PolicyViolationError(
                f"Missing required policy files: {missing}",
                violations=missing,
            )

    async def validate_envelope(
        self, envelope: Dict[str, Any]
    ) -> PolicyValidationResult:
        """
        Validate a policy envelope.

        Args:
            envelope: Policy envelope to validate

        Returns:
            Validation result

        Raises:
            PolicyViolationError: If envelope is invalid
        """
        errors = []
        warnings = []

        # Schema validation
        if self._schema:
            schema_errors = self._validate_schema(envelope)
            errors.extend(schema_errors)

        # Required fields validation
        required_errors = self._validate_required_fields(envelope)
        errors.extend(required_errors)

        # Classification validation
        class_errors = self._validate_classification(envelope)
        errors.extend(class_errors)

        # Approval validation
        approval_errors, approval_warnings = self._validate_approvals(envelope)
        errors.extend(approval_errors)
        warnings.extend(approval_warnings)

        # Budget validation
        budget_warnings = self._validate_budget(envelope)
        warnings.extend(budget_warnings)

        # Time window validation
        time_errors = self._validate_time_window(envelope)
        errors.extend(time_errors)

        # Risk tier validation
        risk_errors = self._validate_risk_tier(envelope)
        errors.extend(risk_errors)

        envelope_hash = self._compute_envelope_hash(envelope)

        result = PolicyValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            envelope_hash=envelope_hash,
            timestamp=datetime.utcnow(),
        )

        if not result.valid:
            raise PolicyViolationError(
                f"Policy envelope validation failed: {errors}",
                violations=errors,
            )

        if warnings:
            for warning in warnings:
                logger.warning(f"Policy warning: {warning}")

        return result

    def _validate_schema(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate envelope against JSON schema."""
        errors = []

        try:
            jsonschema.validate(envelope, self._schema)
        except jsonschema.ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")
        except jsonschema.SchemaError as e:
            errors.append(f"Schema error: {e.message}")

        return errors

    def _validate_required_fields(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate required fields are present."""
        errors = []

        required_fields = [
            "envelope_id",
            "mode",
            "risk_tier",
            "mission_type",
            "classification_level",
            "scope_id",
            "approvals",
            "valid_from",
            "valid_to",
        ]

        for field in required_fields:
            if field not in envelope:
                errors.append(f"Missing required field: {field}")

        return errors

    def _validate_classification(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate classification level."""
        errors = []

        valid_levels = ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]
        level = envelope.get("classification_level")

        if level and level not in valid_levels:
            errors.append(f"Invalid classification level: {level}")

        return errors

    def _validate_approvals(
        self, envelope: Dict[str, Any]
    ) -> tuple[List[str], List[str]]:
        """Validate approvals in envelope."""
        errors = []
        warnings = []

        approvals = envelope.get("approvals", [])

        if not approvals:
            errors.append("At least one approval is required")
            return errors, warnings

        # Check for required approvals based on risk tier
        risk_tier = envelope.get("risk_tier", 1)
        classification = envelope.get("classification_level", "UNCLASS")

        required_roles = self._get_required_approval_roles(risk_tier, classification)
        present_roles = {a.get("role") for a in approvals if a.get("valid", True)}

        missing_roles = set(required_roles) - present_roles
        if missing_roles:
            errors.append(f"Missing required approvals: {list(missing_roles)}")

        # Check approval expiry
        now = datetime.utcnow()
        for approval in approvals:
            expiry = approval.get("expiry")
            if expiry:
                try:
                    expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    if expiry_dt.replace(tzinfo=None) < now:
                        warnings.append(
                            f"Approval from {approval.get('role')} has expired"
                        )
                except ValueError:
                    errors.append(f"Invalid expiry format: {expiry}")

        return errors, warnings

    def _get_required_approval_roles(
        self, risk_tier: int, classification: str
    ) -> List[str]:
        """Determine required approval roles."""
        roles = ["Security"]

        if risk_tier >= 2:
            roles.append("Product")

        if risk_tier >= 3:
            roles.append("AO")

        if classification in ["CUI", "SECRET", "TOPSECRET"]:
            roles.append("GovCompliance")

        if classification in ["SECRET", "TOPSECRET"]:
            roles.append("AO")

        return list(set(roles))  # Remove duplicates

    def _validate_budget(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate budget constraints."""
        warnings = []

        budget = envelope.get("budget_cap", {})

        if not budget:
            warnings.append("No budget cap defined")
            return warnings

        # Check for unreasonably high limits
        if budget.get("cost_usd", 0) > 1000000:
            warnings.append("Budget cap exceeds $1M - verify this is intentional")

        if budget.get("compute_hours", 0) > 10000:
            warnings.append("Compute hours cap exceeds 10000 - verify this is intentional")

        return warnings

    def _validate_time_window(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate time window constraints."""
        errors = []

        valid_from = envelope.get("valid_from")
        valid_to = envelope.get("valid_to")

        if valid_from and valid_to:
            try:
                from_dt = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
                to_dt = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))

                if from_dt >= to_dt:
                    errors.append("valid_from must be before valid_to")

                # Check if window is in the past
                now = datetime.utcnow()
                if to_dt.replace(tzinfo=None) < now:
                    errors.append("Policy envelope validity window has expired")

            except ValueError as e:
                errors.append(f"Invalid datetime format: {e}")

        return errors

    def _validate_risk_tier(self, envelope: Dict[str, Any]) -> List[str]:
        """Validate risk tier configuration."""
        errors = []

        risk_tier = envelope.get("risk_tier")

        if risk_tier is not None:
            if not isinstance(risk_tier, int) or risk_tier < 1 or risk_tier > 3:
                errors.append("risk_tier must be 1, 2, or 3")

            # Risk tier 3 requires AO approval
            if risk_tier == 3:
                approvals = envelope.get("approvals", [])
                ao_approved = any(
                    a.get("role") == "AO" and a.get("valid", True)
                    for a in approvals
                )
                if not ao_approved:
                    errors.append("Risk tier 3 requires AO approval")

        return errors

    def _compute_envelope_hash(self, envelope: Dict[str, Any]) -> str:
        """Compute hash of envelope for integrity verification."""
        # Exclude signature field from hash
        envelope_copy = {k: v for k, v in envelope.items() if k != "signature"}
        envelope_str = json.dumps(envelope_copy, sort_keys=True)
        return f"sha256:{hashlib.sha256(envelope_str.encode()).hexdigest()}"

    async def interpret_constraints(
        self, envelope: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Interpret policy envelope into operational constraints.

        Args:
            envelope: Validated policy envelope

        Returns:
            Operational constraints dictionary
        """
        constraints = {
            "classification_level": envelope.get("classification_level", "UNCLASS"),
            "risk_tier": envelope.get("risk_tier", 1),
            "mission_type": envelope.get("mission_type", "simulation"),
            "mode": envelope.get("mode", "simulation"),
        }

        # ROE constraints
        roe = envelope.get("roe", {})
        constraints["roe"] = {
            "allowed_assets": roe.get("allowed_assets", []),
            "disallowed_assets": roe.get("disallowed_assets", []),
            "allowed_networks": roe.get("allowed_networks", []),
            "allowed_tools": roe.get("allowed_tools", []),
            "disallowed_tools": roe.get("disallowed_tools", []),
            "blast_radius_cap": roe.get("blast_radius_cap", 100),
            "alert_footprint_cap": roe.get("alert_footprint_cap"),
            "lateral_movement_authorized": roe.get("lateral_movement_authorized", False),
            "destructive_ops_authorized": roe.get("destructive_ops_authorized", False),
        }

        # Budget constraints
        budget = envelope.get("budget_cap", {})
        constraints["budget"] = {
            "compute_hours": budget.get("compute_hours", float("inf")),
            "api_calls": budget.get("api_calls", float("inf")),
            "cost_usd": budget.get("cost_usd", float("inf")),
            "soft_limit_percentage": budget.get("soft_limit_percentage", 80),
        }

        # Time constraints
        constraints["time_window"] = {
            "valid_from": envelope.get("valid_from"),
            "valid_to": envelope.get("valid_to"),
            "time_restrictions": roe.get("time_restrictions", False),
        }

        # Operational constraints
        op_constraints = envelope.get("constraints", {})
        constraints["operational"] = {
            "max_concurrent_operations": op_constraints.get("max_concurrent_operations", 5),
            "max_attack_depth": op_constraints.get("max_attack_depth", 10),
            "simulation_runs_required": op_constraints.get("simulation_runs_required", 1000),
            "forensic_completeness_threshold": op_constraints.get(
                "forensic_completeness_threshold", 0.95
            ),
        }

        return constraints

    def cache_envelope(self, envelope_id: str, envelope: Dict[str, Any]) -> None:
        """Cache validated envelope."""
        self._policy_cache[envelope_id] = {
            "envelope": envelope,
            "hash": self._compute_envelope_hash(envelope),
            "cached_at": datetime.utcnow().isoformat(),
        }

    def get_cached_envelope(self, envelope_id: str) -> Optional[Dict[str, Any]]:
        """Get cached envelope."""
        cached = self._policy_cache.get(envelope_id)
        return cached.get("envelope") if cached else None
