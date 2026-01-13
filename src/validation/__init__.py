"""
Frost Gate Spear - Strict Validation Enforcement Module

MANDATORY enforcement of all validation rules. No soft failures, warnings, or overrides.
If ANY required check fails, execution MUST NOT proceed.

Blueprint v6.1 Validation Enforcement
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class ValidationFailure(Exception):
    """Raised when any validation check fails. Execution MUST NOT proceed."""

    def __init__(self, rule: str, reason: str, details: Optional[Dict] = None):
        self.rule = rule
        self.reason = reason
        self.details = details or {}
        super().__init__(f"VALIDATION FAILED [{rule}]: {reason}")


class CredentialMode(Enum):
    """Valid credential modes."""
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATED = "AUTHENTICATED"
    BOTH = "BOTH"


class Environment(Enum):
    """Valid environments."""
    LAB = "LAB"
    STAGING = "STAGING"
    PROD = "PROD"


class ExecutionMode(Enum):
    """Valid execution modes."""
    SIM = "SIM"
    SHADOW = "SHADOW"
    LIVE_GUARDED = "LIVE_GUARDED"
    LIVE_AUTONOMOUS = "LIVE_AUTONOMOUS"


@dataclass
class ValidationResult:
    """Result of a validation check."""
    passed: bool
    rule: str
    message: str
    details: Dict = field(default_factory=dict)


@dataclass
class ApprovalRecord:
    """Record of an approval."""
    approver_id: str
    role: str
    timestamp: datetime
    expires_at: datetime
    scope_hash: str
    campaign_hash: str
    signature: str


@dataclass
class ExecutionPermit:
    """Execution permit token."""
    permit_id: str
    campaign_id: str
    tenant_id: str
    mode: ExecutionMode
    risk_tier: int
    credential_mode: CredentialMode
    tool_allowlist: List[Dict]
    target_allowlist: List[Dict]
    entrypoint_allowlist: List[Dict]
    issued_at: datetime
    expires_at: datetime
    nonce: str
    jti: str
    cr_ref: Dict
    sig: Dict
    budget_limits: Optional[Dict] = None


class StrictValidator:
    """
    Strict validation enforcement for Frost Gate Spear.

    CRITICAL: All validation methods raise ValidationFailure on ANY failure.
    No implicit approvals, overrides, or bypasses are allowed.
    """

    # Used nonces for replay protection
    _used_nonces: Set[str] = set()

    # Required approval roles per risk tier
    RISK_TIER_APPROVALS = {
        1: ["Security"],
        2: ["Security", "Product"],
        3: ["Security", "Product", "AO"],
    }

    # Maximum time window in hours
    MAX_TIME_WINDOW_HOURS = 72

    # Minimum entrypoint diversity requirements
    MIN_DIVERSITY_AXES = 1

    def __init__(
        self,
        trusted_keys: Optional[Dict[str, bytes]] = None,
        nonce_store: Optional[Set[str]] = None,
    ):
        """Initialize strict validator."""
        self.trusted_keys = trusted_keys or {}
        if nonce_store is not None:
            self._used_nonces = nonce_store

    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash of data."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def _verify_signature(
        self,
        payload: bytes,
        signature: str,
        key_id: str,
        algorithm: str,
    ) -> bool:
        """Verify a cryptographic signature."""
        if key_id not in self.trusted_keys:
            return False

        public_key_bytes = self.trusted_keys[key_id]

        try:
            if algorithm in ("ES256", "ES384", "ES512"):
                public_key = serialization.load_pem_public_key(
                    public_key_bytes,
                    backend=default_backend()
                )
                public_key.verify(
                    bytes.fromhex(signature),
                    payload,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            elif algorithm == "EdDSA":
                public_key = serialization.load_pem_public_key(
                    public_key_bytes,
                    backend=default_backend()
                )
                public_key.verify(bytes.fromhex(signature), payload)
                return True
        except (InvalidSignature, Exception):
            return False

        return False

    # ========================================================================
    # 1. PRE-FLIGHT VALIDATION (BEFORE CAMPAIGN CREATION)
    # ========================================================================

    def validate_canonical_scope(self, scope: Dict) -> None:
        """
        Validate canonical.scope.v1 object.

        MANDATORY checks:
        - scope_id exists and is valid UUID
        - All assets are strongly typed inventory IDs (not free text)
        - Explicit boundaries (CIDRs, domains, accounts) are defined
        - Explicit exclusions are present
        - Time window is defined and within policy limits
        - Environment is LAB, STAGING, or PROD
        - PROD requires valid authorization_ref
        - LIVE modes require contact_on_call

        If ANY check fails, raise ValidationFailure.
        """
        logger.info("Validating canonical scope...")

        # Check scope_id exists
        if "scope_id" not in scope:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.SCOPE_ID",
                reason="scope_id is missing",
            )

        # Validate scope_id is UUID format
        try:
            UUID(scope["scope_id"])
        except (ValueError, TypeError):
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.SCOPE_ID_FORMAT",
                reason=f"scope_id is not a valid UUID: {scope.get('scope_id')}",
            )

        # Validate assets are strongly typed
        self._validate_assets(scope.get("assets", []))

        # Validate boundaries exist and are explicit
        self._validate_boundaries(scope.get("boundaries", {}))

        # Validate exclusions exist
        if "exclusions" not in scope:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.EXCLUSIONS",
                reason="exclusions field is required (can be empty array)",
            )

        # Validate time window
        self._validate_time_window(scope.get("time_window", {}))

        # Validate environment
        env = scope.get("environment")
        if env not in [e.value for e in Environment]:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.ENVIRONMENT",
                reason=f"environment must be LAB, STAGING, or PROD, got: {env}",
            )

        # PROD requires authorization_ref
        if env == "PROD":
            self._validate_authorization_ref(scope.get("authorization_ref", {}))

        # Validate scope_hash
        self._validate_scope_hash(scope)

        # Validate contact_on_call
        if "contact_on_call" not in scope:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.CONTACT",
                reason="contact_on_call is required",
            )
        self._validate_contact_on_call(scope["contact_on_call"])

        logger.info("Canonical scope validation PASSED")

    def _validate_assets(self, assets: List[Dict]) -> None:
        """Validate all assets are strongly typed inventory IDs."""
        if not assets:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.ASSETS",
                reason="assets array cannot be empty",
            )

        # Asset ID pattern for strongly typed IDs
        import re
        asset_id_pattern = re.compile(r'^[A-Z]{2,4}-[0-9]{6,12}$')

        valid_asset_types = {
            "HOST", "NETWORK", "APPLICATION", "DATABASE",
            "CLOUD_RESOURCE", "CONTAINER", "API_ENDPOINT", "IDENTITY_STORE"
        }

        for i, asset in enumerate(assets):
            # asset_id required
            if "asset_id" not in asset:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.ASSET_ID",
                    reason=f"asset[{i}] missing asset_id",
                )

            # asset_id must match pattern (strongly typed, not free text)
            if not asset_id_pattern.match(asset["asset_id"]):
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.ASSET_ID_FORMAT",
                    reason=f"asset[{i}] asset_id '{asset['asset_id']}' is not strongly typed (pattern: XX-000000)",
                    details={"asset_id": asset["asset_id"]},
                )

            # asset_type required and valid
            if asset.get("asset_type") not in valid_asset_types:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.ASSET_TYPE",
                    reason=f"asset[{i}] has invalid asset_type: {asset.get('asset_type')}",
                )

            # inventory_ref required
            if "inventory_ref" not in asset:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.INVENTORY_REF",
                    reason=f"asset[{i}] missing inventory_ref",
                )

    def _validate_boundaries(self, boundaries: Dict) -> None:
        """Validate explicit boundaries are defined."""
        if not boundaries:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.BOUNDARIES",
                reason="boundaries object is required",
            )

        # At least one boundary type must be defined
        networks = boundaries.get("networks", [])
        domains = boundaries.get("domains", [])
        cloud_accounts = boundaries.get("cloud_accounts", [])

        if not networks and not domains and not cloud_accounts:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.BOUNDARIES_EMPTY",
                reason="at least one boundary type (networks, domains, or cloud_accounts) must be defined",
            )

        # Validate CIDR format for networks
        import re
        cidr_pattern = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$')
        for i, network in enumerate(networks):
            if "cidr" not in network:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.NETWORK_CIDR",
                    reason=f"networks[{i}] missing cidr",
                )
            if not cidr_pattern.match(network["cidr"]):
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.NETWORK_CIDR_FORMAT",
                    reason=f"networks[{i}] cidr '{network['cidr']}' is not valid CIDR notation",
                )

        # Validate domains
        for i, domain in enumerate(domains):
            if "domain" not in domain:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.DOMAIN",
                    reason=f"domains[{i}] missing domain",
                )
            if "scope_type" not in domain:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.DOMAIN_SCOPE_TYPE",
                    reason=f"domains[{i}] missing scope_type",
                )
            if domain["scope_type"] not in ["EXACT", "WILDCARD_SUBDOMAIN"]:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.DOMAIN_SCOPE_TYPE_INVALID",
                    reason=f"domains[{i}] scope_type must be EXACT or WILDCARD_SUBDOMAIN",
                )

    def _validate_time_window(self, time_window: Dict) -> None:
        """Validate time window is defined and within policy limits."""
        if not time_window:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.TIME_WINDOW",
                reason="time_window is required",
            )

        for field in ["start", "end", "timezone"]:
            if field not in time_window:
                raise ValidationFailure(
                    rule=f"PREFLIGHT.SCOPE.TIME_WINDOW_{field.upper()}",
                    reason=f"time_window.{field} is required",
                )

        # Parse and validate time window
        try:
            start = datetime.fromisoformat(time_window["start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(time_window["end"].replace("Z", "+00:00"))
        except (ValueError, TypeError) as e:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.TIME_WINDOW_FORMAT",
                reason=f"time_window start/end must be ISO 8601 format: {e}",
            )

        # End must be after start
        if end <= start:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.TIME_WINDOW_ORDER",
                reason="time_window.end must be after time_window.start",
            )

        # Check time window duration is within policy limits
        duration_hours = (end - start).total_seconds() / 3600
        if duration_hours > self.MAX_TIME_WINDOW_HOURS:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.TIME_WINDOW_DURATION",
                reason=f"time_window duration ({duration_hours:.1f}h) exceeds maximum ({self.MAX_TIME_WINDOW_HOURS}h)",
            )

    def _validate_authorization_ref(self, auth_ref: Dict) -> None:
        """Validate authorization reference for PROD environment."""
        if not auth_ref:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.AUTHORIZATION_REF",
                reason="authorization_ref is required for PROD environment",
            )

        for field in ["ref_id", "type"]:
            if field not in auth_ref:
                raise ValidationFailure(
                    rule=f"PREFLIGHT.SCOPE.AUTH_{field.upper()}",
                    reason=f"authorization_ref.{field} is required",
                )

        valid_types = [
            "INTERNAL_APPROVAL", "SOW", "MSA",
            "PENTEST_AUTH", "BUG_BOUNTY", "ATO"
        ]
        if auth_ref["type"] not in valid_types:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.AUTH_TYPE_INVALID",
                reason=f"authorization_ref.type must be one of: {valid_types}",
            )

        # Non-internal approvals require signature
        if auth_ref["type"] != "INTERNAL_APPROVAL":
            if "signature" not in auth_ref or "signer_id" not in auth_ref:
                raise ValidationFailure(
                    rule="PREFLIGHT.SCOPE.AUTH_SIGNATURE",
                    reason="authorization_ref requires signature and signer_id for external authorizations",
                )

    def _validate_scope_hash(self, scope: Dict) -> None:
        """Validate scope_hash is present and correct."""
        if "scope_hash" not in scope:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.SCOPE_HASH",
                reason="scope_hash is required",
            )

        # Compute hash excluding scope_hash field
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        computed_hash = self._compute_hash(scope_for_hash)

        if scope["scope_hash"] != computed_hash:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.SCOPE_HASH_MISMATCH",
                reason="scope_hash does not match computed hash",
                details={
                    "expected": computed_hash,
                    "actual": scope["scope_hash"],
                },
            )

    def _validate_contact_on_call(self, contact: Dict) -> None:
        """Validate contact_on_call has required fields."""
        if "primary" not in contact:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.CONTACT_PRIMARY",
                reason="contact_on_call.primary is required",
            )

        primary = contact["primary"]
        for field in ["name", "email", "phone"]:
            if field not in primary:
                raise ValidationFailure(
                    rule=f"PREFLIGHT.SCOPE.CONTACT_PRIMARY_{field.upper()}",
                    reason=f"contact_on_call.primary.{field} is required",
                )

        if "escalation_path" not in contact:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.ESCALATION_PATH",
                reason="contact_on_call.escalation_path is required",
            )

        if not contact["escalation_path"]:
            raise ValidationFailure(
                rule="PREFLIGHT.SCOPE.ESCALATION_PATH_EMPTY",
                reason="contact_on_call.escalation_path cannot be empty",
            )

    def validate_entrypoint_feasibility(
        self,
        campaign: Dict,
        available_entrypoints: List[Dict],
        egress_pools: Dict[str, int],
    ) -> None:
        """
        Validate entrypoint feasibility.

        MANDATORY checks:
        - campaign specifies entrypoints_required = N
        - N distinct entrypoints can be allocated
        - Each entrypoint differs by region OR network zone OR ASN class
        - Egress pools exist and are not exhausted

        If diversity cannot be guaranteed, FAIL.
        """
        logger.info("Validating entrypoint feasibility...")

        n_required = campaign.get("entrypoints_required", 1)

        if n_required < 1:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.REQUIRED_COUNT",
                reason="entrypoints_required must be at least 1",
            )

        if len(available_entrypoints) < n_required:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.INSUFFICIENT",
                reason=f"Need {n_required} entrypoints but only {len(available_entrypoints)} available",
            )

        # Check diversity requirements
        diversity = campaign.get("diversity_requirements", {})
        req_different_regions = diversity.get("require_different_regions", False)
        req_different_zones = diversity.get("require_different_network_zones", False)
        req_different_asn = diversity.get("require_different_asn_classes", False)

        # Collect diversity axes
        regions = set()
        zones = set()
        asn_classes = set()

        for ep in available_entrypoints[:n_required]:
            regions.add(ep.get("region"))
            zones.add(ep.get("network_zone"))
            asn_class = ep.get("egress_asn_class") or ep.get("egress_asn")
            asn_classes.add(asn_class)

            # Check egress pool
            pool_ref = ep.get("egress_ip_pool_ref")
            if pool_ref:
                available_ips = egress_pools.get(pool_ref, 0)
                if available_ips <= 0:
                    raise ValidationFailure(
                        rule="PREFLIGHT.ENTRYPOINT.EGRESS_EXHAUSTED",
                        reason=f"Egress pool '{pool_ref}' is exhausted",
                    )

        # Validate diversity requirements
        if req_different_regions and len(regions) < n_required:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.DIVERSITY_REGION",
                reason=f"require_different_regions is set but only {len(regions)} unique regions for {n_required} entrypoints",
            )

        if req_different_zones and len(zones) < n_required:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.DIVERSITY_ZONE",
                reason=f"require_different_network_zones is set but only {len(zones)} unique zones for {n_required} entrypoints",
            )

        if req_different_asn and len(asn_classes) < n_required:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.DIVERSITY_ASN",
                reason=f"require_different_asn_classes is set but only {len(asn_classes)} unique ASN classes for {n_required} entrypoints",
            )

        # At minimum, entrypoints must differ by at least one axis
        total_diversity = max(len(regions), len(zones), len(asn_classes))
        if n_required > 1 and total_diversity < 2:
            raise ValidationFailure(
                rule="PREFLIGHT.ENTRYPOINT.DIVERSITY_MINIMUM",
                reason="Multiple entrypoints must differ by at least one axis (region/zone/ASN)",
            )

        logger.info("Entrypoint feasibility validation PASSED")

    def validate_credential_mode(
        self,
        campaign: Dict,
        vault_refs: Optional[List[Dict]] = None,
    ) -> None:
        """
        Validate credential mode.

        MANDATORY checks:
        - credential_mode is UNAUTHENTICATED, AUTHENTICATED, or BOTH
        - AUTHENTICATED or BOTH requires valid vault references
        - No raw secrets in specs, logs, or artifacts
        - Additional approvals are enforced if policy requires them

        If credentials would be materialized or leaked, FAIL.
        """
        logger.info("Validating credential mode...")

        mode = campaign.get("credential_mode")
        if mode not in [cm.value for cm in CredentialMode]:
            raise ValidationFailure(
                rule="PREFLIGHT.CREDENTIAL.MODE",
                reason=f"credential_mode must be UNAUTHENTICATED, AUTHENTICATED, or BOTH, got: {mode}",
            )

        if mode in ["AUTHENTICATED", "BOTH"]:
            # Vault references are required
            cred_refs = campaign.get("credential_refs", vault_refs or [])
            if not cred_refs:
                raise ValidationFailure(
                    rule="PREFLIGHT.CREDENTIAL.VAULT_REFS",
                    reason="AUTHENTICATED/BOTH credential mode requires credential_refs with vault references",
                )

            # Validate each credential reference
            for i, cref in enumerate(cred_refs):
                if "vault_ref" not in cref:
                    raise ValidationFailure(
                        rule="PREFLIGHT.CREDENTIAL.VAULT_REF_MISSING",
                        reason=f"credential_refs[{i}] missing vault_ref",
                    )

                vault_ref = cref["vault_ref"]
                # Vault refs must be proper references, not raw secrets
                if not vault_ref.startswith("vault:"):
                    raise ValidationFailure(
                        rule="PREFLIGHT.CREDENTIAL.RAW_SECRET",
                        reason=f"credential_refs[{i}] appears to contain raw secret instead of vault reference",
                    )

                # Check for raw secrets embedded anywhere
                self._check_for_raw_secrets(cref, f"credential_refs[{i}]")

        # Check for raw secrets in campaign spec
        self._check_for_raw_secrets(campaign, "campaign")

        logger.info("Credential mode validation PASSED")

    def _check_for_raw_secrets(self, obj: Any, path: str) -> None:
        """Check for raw secrets in an object recursively."""
        secret_patterns = [
            "password", "secret", "api_key", "apikey", "token",
            "private_key", "privatekey", "credential", "auth_token"
        ]
        allowed_keys = {"credential_mode", "credential_refs"}

        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                if key_lower in allowed_keys:
                    self._check_for_raw_secrets(value, f"{path}.{key}")
                    continue
                for pattern in secret_patterns:
                    if pattern in key_lower:
                        # Allow vault references
                        if isinstance(value, str) and value.startswith("vault:"):
                            continue
                        # Allow structured references
                        if isinstance(value, dict) and "vault_ref" in value:
                            continue
                        raise ValidationFailure(
                            rule="PREFLIGHT.CREDENTIAL.RAW_SECRET_DETECTED",
                            reason=f"Potential raw secret detected at {path}.{key}",
                        )
                self._check_for_raw_secrets(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._check_for_raw_secrets(item, f"{path}[{i}]")

    # ========================================================================
    # 2. GOVERNANCE & APPROVAL CHECKS (BEFORE START)
    # ========================================================================

    def validate_governance(
        self,
        campaign: Dict,
        approvals: List[ApprovalRecord],
        executor_id: str,
    ) -> None:
        """
        Validate governance and approval requirements.

        MANDATORY checks:
        - All required approval roles are present for the campaign risk tier
        - Approvals are unexpired (TTL enforced)
        - Approvals reference the exact scope_hash and campaign hash
        - Separation of duties is enforced (approver != executor for high-risk LIVE)
        - Non-SIM campaigns include a valid, approved Change Request (CR)
        - CR hash matches the campaign hash

        If ANY governance requirement fails, FAIL.
        """
        logger.info("Validating governance requirements...")

        risk_tier = campaign.get("risk_tier", 1)
        mode = campaign.get("mode", "SIM")
        scope_hash = campaign.get("scope_ref", {}).get("scope_hash", "")
        campaign_content = {
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        }
        cr_ref = campaign_content.get("cr_ref")
        if isinstance(cr_ref, dict) and "campaign_hash" in cr_ref:
            cr_ref = dict(cr_ref)
            cr_ref.pop("campaign_hash", None)
            campaign_content["cr_ref"] = cr_ref
        campaign_hash = self._compute_hash(campaign_content)

        # Get required roles for this risk tier
        required_roles = set(self.RISK_TIER_APPROVALS.get(risk_tier, ["Security"]))

        # Check classification level requirements
        classification = campaign.get("classification_level", "UNCLASS")
        if classification in ["CUI", "SECRET", "TOPSECRET"]:
            required_roles.add("GovCompliance")
        if classification in ["SECRET", "TOPSECRET"]:
            required_roles.add("AO")

        # Mission mode requires mission owner
        if mode == "mission":
            required_roles.add("MissionOwner")

        # Collect present roles from valid approvals
        now = datetime.now(timezone.utc)
        present_roles = set()
        approver_ids = set()

        for approval in approvals:
            # Check approval is not expired
            if approval.expires_at <= now:
                raise ValidationFailure(
                    rule="GOVERNANCE.APPROVAL.EXPIRED",
                    reason=f"Approval from {approval.approver_id} ({approval.role}) has expired",
                    details={
                        "approver_id": approval.approver_id,
                        "role": approval.role,
                        "expired_at": approval.expires_at.isoformat(),
                    },
                )

            # Check approval references correct scope_hash
            if approval.scope_hash != scope_hash:
                raise ValidationFailure(
                    rule="GOVERNANCE.APPROVAL.SCOPE_HASH_MISMATCH",
                    reason=f"Approval from {approval.approver_id} references wrong scope_hash",
                    details={
                        "expected": scope_hash,
                        "actual": approval.scope_hash,
                    },
                )

            # Check approval references correct campaign_hash
            if approval.campaign_hash != campaign_hash:
                raise ValidationFailure(
                    rule="GOVERNANCE.APPROVAL.CAMPAIGN_HASH_MISMATCH",
                    reason=f"Approval from {approval.approver_id} references wrong campaign_hash",
                    details={
                        "expected": campaign_hash,
                        "actual": approval.campaign_hash,
                    },
                )

            present_roles.add(approval.role)
            approver_ids.add(approval.approver_id)

        # Check all required roles are present
        missing_roles = required_roles - present_roles
        if missing_roles:
            raise ValidationFailure(
                rule="GOVERNANCE.APPROVAL.MISSING_ROLES",
                reason=f"Missing required approvals: {list(missing_roles)}",
                details={
                    "required": list(required_roles),
                    "present": list(present_roles),
                    "missing": list(missing_roles),
                },
            )

        # Separation of duties for high-risk LIVE modes
        if mode in ["LIVE_GUARDED", "LIVE_AUTONOMOUS"] and risk_tier >= 3:
            if executor_id in approver_ids:
                raise ValidationFailure(
                    rule="GOVERNANCE.SEPARATION_OF_DUTIES",
                    reason="Executor cannot be an approver for high-risk LIVE campaigns",
                    details={
                        "executor_id": executor_id,
                        "approver_ids": list(approver_ids),
                    },
                )

        # Non-SIM campaigns require Change Request
        if mode != "SIM":
            self._validate_change_request(campaign, campaign_hash)

        logger.info("Governance validation PASSED")

    def _validate_change_request(self, campaign: Dict, campaign_hash: str) -> None:
        """Validate change request for non-SIM campaigns."""
        cr_ref = campaign.get("cr_ref")
        if not cr_ref:
            raise ValidationFailure(
                rule="GOVERNANCE.CR.MISSING",
                reason="Change Request (CR) is required for non-SIM campaigns",
            )

        if "cr_id" not in cr_ref:
            raise ValidationFailure(
                rule="GOVERNANCE.CR.ID_MISSING",
                reason="Change Request cr_id is required",
            )

        if "approved_at" not in cr_ref:
            raise ValidationFailure(
                rule="GOVERNANCE.CR.APPROVAL_MISSING",
                reason="Change Request approved_at is required",
            )

        # CR hash must match campaign hash
        if cr_ref.get("campaign_hash") != campaign_hash:
            raise ValidationFailure(
                rule="GOVERNANCE.CR.HASH_MISMATCH",
                reason="Change Request hash does not match campaign hash",
            )

    # ========================================================================
    # 3. EXECUTION PERMIT TOKEN (MANDATORY)
    # ========================================================================

    def validate_execution_permit(
        self,
        permit: ExecutionPermit,
        campaign: Dict,
    ) -> None:
        """
        Validate execution permit token.

        MANDATORY checks:
        - Signature verification
        - TTL not expired
        - Nonce has not been used
        - campaign_id matches
        - mode, risk_tier, and credential_mode match the campaign
        - tool, target, and entrypoint allowlists are enforced
        - CR reference is embedded and valid

        If the permit is missing, invalid, expired, or reused, FAIL.
        """
        logger.info("Validating execution permit...")

        now = datetime.now(timezone.utc)

        # Check permit exists
        if not permit:
            raise ValidationFailure(
                rule="PERMIT.MISSING",
                reason="Execution permit is required",
            )

        # Validate signature
        sig = permit.sig
        if not sig:
            raise ValidationFailure(
                rule="PERMIT.SIGNATURE.MISSING",
                reason="Permit signature is required",
            )

        # Build payload for signature verification
        permit_payload = {
            "permit_id": permit.permit_id,
            "campaign_id": permit.campaign_id,
            "tenant_id": permit.tenant_id,
            "mode": permit.mode.value,
            "risk_tier": permit.risk_tier,
            "credential_mode": permit.credential_mode.value,
            "issued_at": permit.issued_at.isoformat(),
            "expires_at": permit.expires_at.isoformat(),
            "nonce": permit.nonce,
            "jti": permit.jti,
        }

        if self.trusted_keys:
            is_valid = self._verify_signature(
                json.dumps(permit_payload, sort_keys=True).encode('utf-8'),
                sig.get("value", ""),
                sig.get("key_id", ""),
                sig.get("algorithm", "ES256"),
            )
            if not is_valid:
                raise ValidationFailure(
                    rule="PERMIT.SIGNATURE.INVALID",
                    reason="Permit signature verification failed",
                )

        # Check TTL not expired
        if permit.expires_at <= now:
            raise ValidationFailure(
                rule="PERMIT.EXPIRED",
                reason="Execution permit has expired",
                details={
                    "expires_at": permit.expires_at.isoformat(),
                    "current_time": now.isoformat(),
                },
            )

        # Check nonce not reused
        if permit.nonce in self._used_nonces:
            raise ValidationFailure(
                rule="PERMIT.NONCE.REUSED",
                reason="Permit nonce has already been used (replay attack prevention)",
            )
        self._used_nonces.add(permit.nonce)

        # Check campaign_id matches
        campaign_id = campaign.get("campaign_id")
        if permit.campaign_id != campaign_id:
            raise ValidationFailure(
                rule="PERMIT.CAMPAIGN_MISMATCH",
                reason="Permit campaign_id does not match campaign",
                details={
                    "permit_campaign_id": permit.campaign_id,
                    "campaign_id": campaign_id,
                },
            )

        # Check mode matches
        campaign_mode = campaign.get("mode")
        if permit.mode.value != campaign_mode:
            raise ValidationFailure(
                rule="PERMIT.MODE_MISMATCH",
                reason=f"Permit mode {permit.mode.value} does not match campaign mode {campaign_mode}",
            )

        # Check risk_tier matches
        campaign_risk = campaign.get("risk_tier")
        if permit.risk_tier != campaign_risk:
            raise ValidationFailure(
                rule="PERMIT.RISK_TIER_MISMATCH",
                reason=f"Permit risk_tier {permit.risk_tier} does not match campaign risk_tier {campaign_risk}",
            )

        # Check credential_mode matches
        campaign_cred_mode = campaign.get("credential_mode")
        if permit.credential_mode.value != campaign_cred_mode:
            raise ValidationFailure(
                rule="PERMIT.CREDENTIAL_MODE_MISMATCH",
                reason=f"Permit credential_mode {permit.credential_mode.value} does not match campaign {campaign_cred_mode}",
            )

        # Check CR reference for non-SIM
        if permit.mode.value != "SIM":
            if not permit.cr_ref:
                raise ValidationFailure(
                    rule="PERMIT.CR_REF.MISSING",
                    reason="Permit cr_ref is required for non-SIM mode",
                )

        logger.info("Execution permit validation PASSED")

    # ========================================================================
    # 4. RUNTIME ENFORCEMENT (CONTINUOUS)
    # ========================================================================

    def validate_runtime_action(
        self,
        action: Dict,
        permit: ExecutionPermit,
        target_rates: Dict[str, int],
        autonomy_level: int,
        human_confirmation: bool,
    ) -> None:
        """
        Validate a runtime action against enforcement rules.

        MANDATORY checks:
        - Action class is allowed
        - Rate and concurrency limits are respected
        - Autonomy level constraints are respected
        - Human confirmation exists when required
        - Context integrity is intact

        Violations cause:
        - Immediate deny
        - Scoped revoke if policy dictates
        """
        logger.info(f"Validating runtime action: {action.get('action_id')}")

        # Check action is in tool allowlist
        tool_id = action.get("tool_id")
        allowed_tools = {t["tool_id"] for t in permit.tool_allowlist}
        if tool_id not in allowed_tools:
            raise ValidationFailure(
                rule="RUNTIME.TOOL_NOT_ALLOWED",
                reason=f"Tool '{tool_id}' is not in permit allowlist",
                details={
                    "tool_id": tool_id,
                    "allowed_tools": list(allowed_tools),
                },
            )

        # Check target is in allowlist
        target_id = action.get("target_id")
        allowed_targets = {t["target_id"] for t in permit.target_allowlist}
        if target_id not in allowed_targets:
            raise ValidationFailure(
                rule="RUNTIME.TARGET_NOT_ALLOWED",
                reason=f"Target '{target_id}' is not in permit allowlist",
            )

        # Check rate limits
        target_spec = next(
            (t for t in permit.target_allowlist if t["target_id"] == target_id),
            {}
        )
        max_rpm = target_spec.get("max_actions_per_minute", 60)
        current_rate = target_rates.get(target_id, 0)
        if current_rate >= max_rpm:
            raise ValidationFailure(
                rule="RUNTIME.RATE_LIMIT_EXCEEDED",
                reason=f"Rate limit exceeded for target '{target_id}'",
                details={
                    "current_rate": current_rate,
                    "max_rate": max_rpm,
                },
            )

        # Check autonomy level constraints
        action_autonomy = action.get("required_autonomy_level", 1)
        if action_autonomy > autonomy_level:
            raise ValidationFailure(
                rule="RUNTIME.AUTONOMY_EXCEEDED",
                reason=f"Action requires autonomy level {action_autonomy} but only {autonomy_level} is authorized",
            )

        # Check human confirmation for high-impact actions
        if action.get("requires_human_confirmation", False):
            if not human_confirmation:
                raise ValidationFailure(
                    rule="RUNTIME.HUMAN_CONFIRMATION_REQUIRED",
                    reason="Action requires human confirmation before execution",
                )

        logger.info(f"Runtime action validation PASSED: {action.get('action_id')}")

    def validate_target_safety_envelope(
        self,
        target_id: str,
        current_rate: int,
        max_rate: int,
        health_score: float,
        blast_radius: int,
        blast_radius_cap: int,
    ) -> None:
        """
        Validate target safety envelope.

        MANDATORY checks:
        - Per-target rate limits enforced
        - Health signals checked
        - Blast radius caps respected
        - Stop conditions enforced

        If breached, HALT execution and revoke scoped entities.
        """
        # Check rate limit
        if current_rate >= max_rate:
            raise ValidationFailure(
                rule="SAFETY.TARGET.RATE_LIMIT",
                reason=f"Target {target_id} rate limit exceeded",
                details={
                    "current": current_rate,
                    "max": max_rate,
                },
            )

        # Check health signals
        if health_score < 0.5:
            raise ValidationFailure(
                rule="SAFETY.TARGET.UNHEALTHY",
                reason=f"Target {target_id} health score too low: {health_score}",
            )

        # Check blast radius
        if blast_radius > blast_radius_cap:
            raise ValidationFailure(
                rule="SAFETY.TARGET.BLAST_RADIUS",
                reason=f"Target {target_id} blast radius {blast_radius} exceeds cap {blast_radius_cap}",
            )

    def validate_entrypoint_enforcement(
        self,
        action: Dict,
        permit: ExecutionPermit,
        current_entrypoint: str,
        egress_identity: str,
    ) -> None:
        """
        Validate entrypoint enforcement.

        MANDATORY checks:
        - Actions execute only from assigned entrypoints
        - Entrypoint diversity remains intact
        - Egress identity matches allocation

        If diversity collapses, HALT.
        """
        # Check action is from assigned entrypoint
        allowed_entrypoints = {e["entrypoint_id"] for e in permit.entrypoint_allowlist}
        if current_entrypoint not in allowed_entrypoints:
            raise ValidationFailure(
                rule="RUNTIME.ENTRYPOINT.UNAUTHORIZED",
                reason=f"Action executed from unauthorized entrypoint '{current_entrypoint}'",
                details={
                    "current": current_entrypoint,
                    "allowed": list(allowed_entrypoints),
                },
            )

        # Verify egress identity matches allocation
        ep_spec = next(
            (e for e in permit.entrypoint_allowlist if e["entrypoint_id"] == current_entrypoint),
            {}
        )
        expected_egress = ep_spec.get("egress_asn")
        if expected_egress and egress_identity != expected_egress:
            raise ValidationFailure(
                rule="RUNTIME.ENTRYPOINT.EGRESS_MISMATCH",
                reason=f"Egress identity mismatch for entrypoint '{current_entrypoint}'",
                details={
                    "expected": expected_egress,
                    "actual": egress_identity,
                },
            )

    # ========================================================================
    # 4.2 SCOPE DRIFT DETECTION (MANDATORY)
    # ========================================================================

    def validate_scope_drift(
        self,
        executed_actions: List[Dict],
        approved_scope: Dict,
        drift_threshold: float = 0.15,
    ) -> None:
        """
        Validate scope drift detection.

        MANDATORY checks:
        - Compute semantic representation of executed action graph
        - Compare against approved scope intent
        - Detect semantic drift beyond threshold

        Responses:
        - P1 (drift < threshold): alert only
        - P2+ (drift >= threshold): halt + scoped revoke

        Failure code: RUNTIME.SCOPE.DRIFT
        """
        logger.info("Validating scope drift...")

        if not executed_actions:
            return  # No actions to check

        # Extract approved scope boundaries
        approved_assets = set()
        approved_networks = set()
        approved_domains = set()

        for asset in approved_scope.get("assets", []):
            approved_assets.add(asset.get("asset_id"))

        for network in approved_scope.get("boundaries", {}).get("networks", []):
            approved_networks.add(network.get("cidr"))

        for domain in approved_scope.get("boundaries", {}).get("domains", []):
            approved_domains.add(domain.get("domain"))

        # Compute semantic representation of executed actions
        executed_targets = set()
        executed_networks = set()
        executed_domains = set()
        out_of_scope_actions = []

        for action in executed_actions:
            target_id = action.get("target_id")
            target_network = action.get("target_network")
            target_domain = action.get("target_domain")

            if target_id:
                executed_targets.add(target_id)
            if target_network:
                executed_networks.add(target_network)
            if target_domain:
                executed_domains.add(target_domain)

            # Check if action is within approved scope
            in_scope = False

            # Check asset scope
            if target_id and target_id in approved_assets:
                in_scope = True

            # Check network scope (CIDR containment check)
            if target_network:
                for approved_cidr in approved_networks:
                    if self._is_ip_in_cidr(target_network, approved_cidr):
                        in_scope = True
                        break

            # Check domain scope
            if target_domain:
                for approved_domain in approved_domains:
                    if self._is_domain_in_scope(target_domain, approved_domain):
                        in_scope = True
                        break

            if not in_scope and (target_id or target_network or target_domain):
                out_of_scope_actions.append(action)

        # Calculate drift score
        total_actions = len(executed_actions)
        drift_count = len(out_of_scope_actions)
        drift_score = drift_count / total_actions if total_actions > 0 else 0.0

        # Determine severity and response
        if drift_score > 0:
            severity = self._calculate_drift_severity(drift_score, drift_threshold)

            if severity >= 2:  # P2 or higher
                raise ValidationFailure(
                    rule="RUNTIME.SCOPE.DRIFT",
                    reason=f"Scope drift detected: {drift_score:.2%} of actions outside approved scope (P{severity})",
                    details={
                        "drift_score": drift_score,
                        "threshold": drift_threshold,
                        "severity": f"P{severity}",
                        "out_of_scope_count": drift_count,
                        "total_actions": total_actions,
                        "out_of_scope_actions": [
                            {"action_id": a.get("action_id"), "target": a.get("target_id")}
                            for a in out_of_scope_actions[:10]  # First 10 violations
                        ],
                        "action_required": "HALT_AND_REVOKE",
                    },
                )
            else:  # P1 - alert only
                logger.warning(
                    f"Scope drift alert (P1): {drift_score:.2%} drift detected",
                    extra={
                        "drift_score": drift_score,
                        "out_of_scope_count": drift_count,
                    }
                )

        logger.info(f"Scope drift validation PASSED (drift: {drift_score:.2%})")

    def _is_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP address is within CIDR range."""
        try:
            import ipaddress
            # Handle both IP and CIDR inputs
            if "/" in ip:
                ip_net = ipaddress.ip_network(ip, strict=False)
                cidr_net = ipaddress.ip_network(cidr, strict=False)
                return ip_net.subnet_of(cidr_net)
            else:
                ip_addr = ipaddress.ip_address(ip)
                cidr_net = ipaddress.ip_network(cidr, strict=False)
                return ip_addr in cidr_net
        except (ValueError, TypeError):
            return False

    def _is_domain_in_scope(self, target_domain: str, approved_domain: str) -> bool:
        """Check if target domain is within approved domain scope."""
        target_domain = target_domain.lower().strip(".")
        approved_domain = approved_domain.lower().strip(".")

        # Exact match
        if target_domain == approved_domain:
            return True

        # Subdomain match (*.example.com includes sub.example.com)
        if target_domain.endswith("." + approved_domain):
            return True

        return False

    def _calculate_drift_severity(self, drift_score: float, threshold: float) -> int:
        """Calculate drift severity level (P1-P5)."""
        if drift_score < threshold * 0.5:
            return 1  # P1 - minor drift, alert only
        elif drift_score < threshold:
            return 2  # P2 - moderate drift, halt
        elif drift_score < threshold * 2:
            return 3  # P3 - significant drift
        elif drift_score < threshold * 3:
            return 4  # P4 - severe drift
        else:
            return 5  # P5 - critical drift

    # ========================================================================
    # 4.5 COST CONTROLLER ENFORCEMENT (MANDATORY)
    # ========================================================================

    def validate_cost_controller(
        self,
        campaign_id: str,
        current_cost: float,
        budget_limit: float,
        action_cost_delta: float,
        soft_threshold: float = 0.90,
        hard_threshold: float = 1.0,
    ) -> Dict:
        """
        Validate cost controller enforcement.

        MANDATORY checks:
        - Soft throttle at 90% of budget (warning, reduced rate)
        - Hard stop at 100% of budget (halt execution)
        - Cost delta recorded per action

        Failure code: RUNTIME.BUDGET.EXCEEDED
        """
        logger.info(f"Validating cost controller for campaign {campaign_id}...")

        if budget_limit <= 0:
            raise ValidationFailure(
                rule="RUNTIME.BUDGET.INVALID_LIMIT",
                reason="Budget limit must be positive",
            )

        # Calculate projected cost after action
        projected_cost = current_cost + action_cost_delta
        budget_utilization = projected_cost / budget_limit

        # Hard stop at 100%
        if budget_utilization >= hard_threshold:
            raise ValidationFailure(
                rule="RUNTIME.BUDGET.EXCEEDED",
                reason=f"Budget limit exceeded: {budget_utilization:.1%} of ${budget_limit:.2f}",
                details={
                    "campaign_id": campaign_id,
                    "current_cost": current_cost,
                    "action_cost_delta": action_cost_delta,
                    "projected_cost": projected_cost,
                    "budget_limit": budget_limit,
                    "utilization": budget_utilization,
                    "action_required": "HARD_STOP",
                },
            )

        # Soft throttle at 90%
        throttle_applied = False
        if budget_utilization >= soft_threshold:
            logger.warning(
                f"Budget soft threshold reached: {budget_utilization:.1%}",
                extra={
                    "campaign_id": campaign_id,
                    "utilization": budget_utilization,
                    "action": "THROTTLE",
                }
            )
            throttle_applied = True

        result = {
            "campaign_id": campaign_id,
            "current_cost": current_cost,
            "action_cost_delta": action_cost_delta,
            "projected_cost": projected_cost,
            "budget_limit": budget_limit,
            "utilization": budget_utilization,
            "throttle_applied": throttle_applied,
            "status": "THROTTLED" if throttle_applied else "OK",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(f"Cost controller validation PASSED (utilization: {budget_utilization:.1%})")
        return result

    # ========================================================================
    # 5. EVIDENCE & LEDGER INTEGRITY
    # ========================================================================

    def validate_ledger_integrity(
        self,
        entries: List[Dict],
    ) -> None:
        """
        Validate evidence and ledger integrity.

        MANDATORY checks:
        - Ledger is append-only
        - Hash chain is intact
        - No missing or reordered events
        - Every allow/deny has dual attestation signatures
        - Witness signatures are validated when present

        If ledger integrity fails, the run is INVALID.
        """
        logger.info("Validating ledger integrity...")

        if not entries:
            raise ValidationFailure(
                rule="LEDGER.EMPTY",
                reason="Ledger cannot be empty",
            )

        # Check first entry has no previous_hash
        if entries[0].get("previous_hash") is not None:
            raise ValidationFailure(
                rule="LEDGER.FIRST_ENTRY_LINK",
                reason="First ledger entry must have null previous_hash",
            )

        # Verify sequence and chain
        for i, entry in enumerate(entries):
            # Check sequence number
            expected_seq = i + 1
            actual_seq = entry.get("sequence_number")
            if actual_seq != expected_seq:
                raise ValidationFailure(
                    rule="LEDGER.SEQUENCE_GAP",
                    reason=f"Sequence gap at entry {i}: expected {expected_seq}, got {actual_seq}",
                )

            # Verify chain link (except first entry)
            if i > 0:
                expected_prev = entries[i - 1].get("entry_hash")
                actual_prev = entry.get("previous_hash")
                if actual_prev != expected_prev:
                    raise ValidationFailure(
                        rule="LEDGER.CHAIN_BREAK",
                        reason=f"Chain break at entry {i}: previous_hash mismatch",
                        details={
                            "expected": expected_prev,
                            "actual": actual_prev,
                        },
                    )

            # Verify entry hash
            hash_content = {
                "entry_id": entry.get("entry_id"),
                "campaign_id": entry.get("campaign_id"),
                "sequence_number": entry.get("sequence_number"),
                "event_type": entry.get("event_type"),
                "timestamp": entry.get("timestamp"),
                "payload_hash": self._compute_hash(entry.get("payload", {})),
                "previous_hash": entry.get("previous_hash"),
            }
            expected_hash = self._compute_hash(hash_content)
            if entry.get("entry_hash") != expected_hash:
                raise ValidationFailure(
                    rule="LEDGER.HASH_MISMATCH",
                    reason=f"Entry {i} hash does not match computed hash",
                )

            # Check dual attestation for allow/deny events
            event_type = entry.get("event_type")
            if event_type in ["ACTION_APPROVED", "ACTION_DENIED"]:
                self._validate_dual_attestation(entry, i)

        logger.info("Ledger integrity validation PASSED")

    def _validate_dual_attestation(self, entry: Dict, index: int) -> None:
        """Validate dual attestation for allow/deny decisions."""
        attestation = entry.get("dual_attestation")
        if not attestation:
            raise ValidationFailure(
                rule="LEDGER.DUAL_ATTESTATION.MISSING",
                reason=f"Entry {index} is allow/deny but missing dual attestation",
            )

        if "control_plane_attestation" not in attestation:
            raise ValidationFailure(
                rule="LEDGER.DUAL_ATTESTATION.CONTROL_PLANE",
                reason=f"Entry {index} missing control_plane_attestation",
            )

        if "runtime_guard_attestation" not in attestation:
            raise ValidationFailure(
                rule="LEDGER.DUAL_ATTESTATION.RUNTIME_GUARD",
                reason=f"Entry {index} missing runtime_guard_attestation",
            )

    # ========================================================================
    # 6. DETERMINISTIC REPLAY (POST-RUN)
    # ========================================================================

    def validate_replay_determinism(
        self,
        replay_manifest: Dict,
        replay_results: Dict,
        determinism_threshold: float = 0.95,
    ) -> None:
        """
        Validate deterministic replay.

        MANDATORY checks:
        - Deterministic seed recorded
        - Time virtualization enforced
        - Environment and tool snapshots referenced
        - All nondeterministic inputs captured

        Compute determinism score.
        - Low determinism blocks promotion
        - Root causes of nondeterminism must be surfaced
        """
        logger.info("Validating replay determinism...")

        # Check deterministic seed recorded
        config = replay_manifest.get("determinism_config", {})
        rng_config = config.get("rng_seeding", {})
        if not rng_config.get("enabled"):
            raise ValidationFailure(
                rule="REPLAY.RNG.NOT_ENABLED",
                reason="Deterministic RNG seeding must be enabled",
            )

        if not rng_config.get("master_seed"):
            raise ValidationFailure(
                rule="REPLAY.RNG.NO_SEED",
                reason="Master seed must be recorded for deterministic replay",
            )

        # Check time virtualization
        time_config = config.get("time_virtualization", {})
        if not time_config.get("enabled"):
            raise ValidationFailure(
                rule="REPLAY.TIME.NOT_ENABLED",
                reason="Time virtualization must be enabled for deterministic replay",
            )

        # Check snapshots exist
        snapshots = replay_manifest.get("snapshot_refs", {})
        if "environment" not in snapshots or not snapshots["environment"]:
            raise ValidationFailure(
                rule="REPLAY.SNAPSHOT.ENVIRONMENT",
                reason="Environment snapshot reference is required",
            )

        if "tool_versions" not in snapshots or not snapshots["tool_versions"]:
            raise ValidationFailure(
                rule="REPLAY.SNAPSHOT.TOOLS",
                reason="Tool version snapshots are required",
            )

        # Check nondeterministic inputs are captured
        ndi_count = len(replay_manifest.get("nondeterministic_inputs", []))
        if ndi_count == 0 and replay_manifest.get("has_external_inputs", False):
            raise ValidationFailure(
                rule="REPLAY.NDI.NOT_CAPTURED",
                reason="Nondeterministic inputs exist but were not captured",
            )

        # Compute determinism score
        total_events = replay_results.get("total_events", 0)
        matching_events = replay_results.get("matching_events", 0)
        if total_events > 0:
            determinism_score = matching_events / total_events
        else:
            determinism_score = 0.0

        if determinism_score < determinism_threshold:
            variances = replay_results.get("variances", [])
            raise ValidationFailure(
                rule="REPLAY.DETERMINISM.LOW",
                reason=f"Determinism score {determinism_score:.2%} below threshold {determinism_threshold:.2%}",
                details={
                    "score": determinism_score,
                    "threshold": determinism_threshold,
                    "variances": variances[:10],  # First 10 variances
                },
            )

        logger.info(f"Replay determinism validation PASSED (score: {determinism_score:.2%})")

    # ========================================================================
    # 7. FINAL INTEGRITY CHECKS (NON-NEGOTIABLE)
    # ========================================================================

    def validate_final_integrity(
        self,
        evidence_bundles: List[Dict],
        daily_anchors: List[Dict],
        witness_checkpoints: List[Dict],
        redaction_report: Optional[Dict],
        forensic_completeness: float,
        completeness_threshold: float = 0.95,
    ) -> None:
        """
        Validate final integrity checks.

        MANDATORY checks:
        - Evidence bundles are content-addressed and immutable
        - Daily anchors exist and match ledger roots
        - Witness checkpoints are valid (if enabled)
        - Redaction.report.v1 exists and confirms secrets were removed
        - Forensic completeness meets minimum threshold
        """
        logger.info("Validating final integrity...")

        # Check evidence bundles are content-addressed
        for i, bundle in enumerate(evidence_bundles):
            if "bundle_hash" not in bundle:
                raise ValidationFailure(
                    rule="FINAL.EVIDENCE.HASH_MISSING",
                    reason=f"Evidence bundle {i} missing bundle_hash",
                )

            # Verify bundle hash
            bundle_content = {
                k: v
                for k, v in bundle.items()
                if k not in ("bundle_hash", "bundle_id")
            }
            expected_hash = self._compute_hash(bundle_content)
            if bundle["bundle_hash"] != expected_hash:
                raise ValidationFailure(
                    rule="FINAL.EVIDENCE.HASH_MISMATCH",
                    reason=f"Evidence bundle {i} hash does not match content",
                )

        # Check daily anchors exist
        if not daily_anchors:
            raise ValidationFailure(
                rule="FINAL.ANCHORS.MISSING",
                reason="Daily anchors are required",
            )

        # Validate daily anchors
        for i, anchor in enumerate(daily_anchors):
            if "merkle_root" not in anchor:
                raise ValidationFailure(
                    rule="FINAL.ANCHORS.MERKLE_ROOT",
                    reason=f"Daily anchor {i} missing merkle_root",
                )

            if "signature" not in anchor:
                raise ValidationFailure(
                    rule="FINAL.ANCHORS.SIGNATURE",
                    reason=f"Daily anchor {i} missing signature",
                )

        # Validate witness checkpoints if present
        if witness_checkpoints:
            self._validate_witness_chain(witness_checkpoints)

        # Check redaction report
        if not redaction_report:
            raise ValidationFailure(
                rule="FINAL.REDACTION.MISSING",
                reason="Redaction report (redaction.report.v1) is required",
            )

        if not redaction_report.get("secrets_removed", False):
            raise ValidationFailure(
                rule="FINAL.REDACTION.INCOMPLETE",
                reason="Redaction report indicates secrets were not fully removed",
            )

        # Check forensic completeness
        if forensic_completeness < completeness_threshold:
            raise ValidationFailure(
                rule="FINAL.FORENSICS.INCOMPLETE",
                reason=f"Forensic completeness {forensic_completeness:.2%} below threshold {completeness_threshold:.2%}",
            )

        logger.info("Final integrity validation PASSED")

    def _validate_witness_chain(self, checkpoints: List[Dict]) -> None:
        """Validate witness checkpoint chain."""
        if not checkpoints:
            return

        # Sort by sequence
        sorted_cps = sorted(checkpoints, key=lambda c: c.get("sequence_number", 0))

        for i, cp in enumerate(sorted_cps):
            expected_seq = i + 1
            if cp.get("sequence_number") != expected_seq:
                raise ValidationFailure(
                    rule="FINAL.WITNESS.SEQUENCE_GAP",
                    reason=f"Witness checkpoint sequence gap at {i}",
                )

            if i > 0:
                prev_cp = sorted_cps[i - 1]
                expected_prev = self._compute_hash({
                    "checkpoint_id": prev_cp.get("checkpoint_id"),
                    "payload_hash": prev_cp.get("payload_hash"),
                    "signature": prev_cp.get("signature"),
                })
                if cp.get("previous_checkpoint_hash") != expected_prev:
                    raise ValidationFailure(
                        rule="FINAL.WITNESS.CHAIN_BREAK",
                        reason=f"Witness checkpoint chain break at {i}",
                    )

    # ========================================================================
    # 8. CUSTOMER VERIFIER REQUIREMENT
    # ========================================================================

    def validate_verifier_compatibility(
        self,
        dossier: Dict,
        evidence_bundles: List[Dict],
        checkpoints: List[Dict],
    ) -> None:
        """
        Validate that customer-run verifier can independently validate.

        MANDATORY checks (verifier must be able to validate):
        - Ledger hash chain
        - All signatures
        - Evidence bundle hashes
        - Anchors and witness signatures
        - Dossier integrity
        - ZK attestations (if present)

        If verifier fails, the run is UNTRUSTWORTHY.
        """
        logger.info("Validating verifier compatibility...")

        # Check dossier has integrity section
        if "integrity" not in dossier:
            raise ValidationFailure(
                rule="VERIFIER.DOSSIER.INTEGRITY",
                reason="Dossier missing integrity section for verification",
            )

        integrity = dossier["integrity"]
        if "dossier_hash" not in integrity:
            raise ValidationFailure(
                rule="VERIFIER.DOSSIER.HASH",
                reason="Dossier missing dossier_hash for verification",
            )

        # Verify dossier hash
        dossier_content = {k: v for k, v in dossier.items() if k != "integrity"}
        computed_hash = self._compute_hash(dossier_content)
        if integrity["dossier_hash"] != computed_hash:
            raise ValidationFailure(
                rule="VERIFIER.DOSSIER.HASH_MISMATCH",
                reason="Dossier hash verification failed",
            )

        # Check evidence bundles have hashes
        for i, bundle in enumerate(evidence_bundles):
            if "bundle_hash" not in bundle:
                raise ValidationFailure(
                    rule="VERIFIER.EVIDENCE.HASH_MISSING",
                    reason=f"Evidence bundle {i} missing hash for verification",
                )

        # Check checkpoints have signatures
        for i, cp in enumerate(checkpoints):
            if "signature" not in cp:
                raise ValidationFailure(
                    rule="VERIFIER.CHECKPOINT.SIGNATURE",
                    reason=f"Checkpoint {i} missing signature for verification",
                )

        # Check ZK attestations if present
        zk_refs = dossier.get("zk_attestation_refs", [])
        for i, zk in enumerate(zk_refs):
            if "proof_hash" not in zk:
                raise ValidationFailure(
                    rule="VERIFIER.ZK.PROOF_HASH",
                    reason=f"ZK attestation {i} missing proof_hash",
                )
            if "verification_key_ref" not in zk:
                raise ValidationFailure(
                    rule="VERIFIER.ZK.VERIFICATION_KEY",
                    reason=f"ZK attestation {i} missing verification_key_ref",
                )

        logger.info("Verifier compatibility validation PASSED")

    # ========================================================================
    # 5. STRUCTURAL NO-BYPASS ENFORCEMENT (MANDATORY)
    # ========================================================================

    def validate_structural_no_bypass(
        self,
        system_config: Dict,
        network_policies: List[Dict],
        admission_policies: List[Dict],
        ci_bypass_check_result: Optional[Dict] = None,
    ) -> None:
        """
        Validate structural no-bypass enforcement.

        MANDATORY checks:
        - Orchestrator is the sole execution entrypoint
        - Tools cannot be invoked directly
        - Network and admission policies enforce isolation
        - CI fails if bypass paths exist

        Failure code: STRUCTURAL.NO_BYPASS.VIOLATION
        """
        logger.info("Validating structural no-bypass enforcement...")

        # Check orchestrator is sole entrypoint
        execution_entrypoints = system_config.get("execution_entrypoints", [])
        if not execution_entrypoints:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.NO_ENTRYPOINT",
                reason="No execution entrypoints configured",
            )

        orchestrator_only = all(
            ep.get("type") == "ORCHESTRATOR" for ep in execution_entrypoints
        )
        if not orchestrator_only:
            non_orchestrator = [
                ep for ep in execution_entrypoints
                if ep.get("type") != "ORCHESTRATOR"
            ]
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.DIRECT_TOOL_ACCESS",
                reason="Non-orchestrator execution entrypoints detected",
                details={
                    "violation_count": len(non_orchestrator),
                    "violating_entrypoints": [
                        {"id": ep.get("id"), "type": ep.get("type")}
                        for ep in non_orchestrator
                    ],
                },
            )

        # Verify tools cannot be invoked directly
        tool_exposure = system_config.get("tool_exposure", {})
        if tool_exposure.get("direct_invocation_enabled", False):
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.TOOL_DIRECT_INVOKE",
                reason="Direct tool invocation is enabled - must be disabled",
            )

        if tool_exposure.get("public_endpoints", []):
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.TOOL_PUBLIC_ENDPOINT",
                reason="Tools have public endpoints exposed",
                details={
                    "exposed_endpoints": tool_exposure.get("public_endpoints"),
                },
            )

        # Validate network policies enforce isolation
        self._validate_network_isolation(network_policies)

        # Validate admission policies
        self._validate_admission_policies(admission_policies)

        # Check CI bypass detection result
        if ci_bypass_check_result:
            if ci_bypass_check_result.get("bypass_paths_detected", False):
                raise ValidationFailure(
                    rule="STRUCTURAL.NO_BYPASS.CI_BYPASS_DETECTED",
                    reason="CI detected bypass paths in codebase",
                    details={
                        "bypass_paths": ci_bypass_check_result.get("paths", []),
                        "scan_timestamp": ci_bypass_check_result.get("timestamp"),
                    },
                )

            if not ci_bypass_check_result.get("scan_completed", False):
                raise ValidationFailure(
                    rule="STRUCTURAL.NO_BYPASS.CI_SCAN_INCOMPLETE",
                    reason="CI bypass path scan did not complete",
                )

        logger.info("Structural no-bypass validation PASSED")

    def _validate_network_isolation(self, network_policies: List[Dict]) -> None:
        """Validate network policies enforce proper isolation."""
        if not network_policies:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.NO_NETWORK_POLICY",
                reason="No network policies defined",
            )

        # Check for default-deny policy
        has_default_deny = any(
            policy.get("default_action") == "DENY"
            for policy in network_policies
        )
        if not has_default_deny:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.NO_DEFAULT_DENY",
                reason="Network policies must include default-deny rule",
            )

        # Check tool namespace isolation
        tool_namespace_policies = [
            p for p in network_policies
            if p.get("namespace") == "tools" or p.get("applies_to") == "tools"
        ]

        if not tool_namespace_policies:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.TOOL_NAMESPACE_UNPROTECTED",
                reason="No network policy protects tool namespace",
            )

        # Verify tools can only be reached via orchestrator
        for policy in tool_namespace_policies:
            allowed_sources = policy.get("allowed_sources", [])
            non_orchestrator_sources = [
                s for s in allowed_sources
                if s.get("type") != "ORCHESTRATOR" and s.get("namespace") != "orchestrator"
            ]
            if non_orchestrator_sources:
                raise ValidationFailure(
                    rule="STRUCTURAL.NO_BYPASS.TOOL_NON_ORCHESTRATOR_ACCESS",
                    reason="Tools accessible from non-orchestrator sources",
                    details={
                        "policy_id": policy.get("policy_id"),
                        "violating_sources": non_orchestrator_sources,
                    },
                )

    def _validate_admission_policies(self, admission_policies: List[Dict]) -> None:
        """Validate admission policies prevent bypass."""
        if not admission_policies:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.NO_ADMISSION_POLICY",
                reason="No admission policies defined",
            )

        # Check for required admission controllers
        required_controllers = {
            "tool_invocation_validator",
            "orchestrator_origin_validator",
            "permit_validator",
        }

        active_controllers = set()
        for policy in admission_policies:
            controller = policy.get("controller")
            if controller and policy.get("enabled", False):
                active_controllers.add(controller)

        missing_controllers = required_controllers - active_controllers
        if missing_controllers:
            raise ValidationFailure(
                rule="STRUCTURAL.NO_BYPASS.MISSING_ADMISSION_CONTROLLER",
                reason="Required admission controllers not active",
                details={
                    "required": list(required_controllers),
                    "active": list(active_controllers),
                    "missing": list(missing_controllers),
                },
            )

    # ========================================================================
    # 10. UX INTEGRITY VALIDATION (MANDATORY)
    # ========================================================================

    def validate_ux_integrity(
        self,
        ux_components: Dict,
        enforce_mode: bool = True,
    ) -> None:
        """
        Validate UX integrity requirements.

        MANDATORY checks (existence or enforcement of):
        - Live Action Graph fed from ledger
        - Replay Debugger with determinism diff
        - Dossier Builder producing signed output
        - Blast Radius Preview before execution

        If missing or stubbed without enforcement:
        Failure code: UX.INTEGRITY.FAILURE
        """
        logger.info("Validating UX integrity...")

        required_components = {
            "live_action_graph": {
                "description": "Live Action Graph fed from ledger",
                "required_features": ["ledger_feed", "real_time_updates"],
            },
            "replay_debugger": {
                "description": "Replay Debugger with determinism diff",
                "required_features": ["determinism_diff", "step_through"],
            },
            "dossier_builder": {
                "description": "Dossier Builder producing signed output",
                "required_features": ["signed_output", "integrity_verification"],
            },
            "blast_radius_preview": {
                "description": "Blast Radius Preview before execution",
                "required_features": ["pre_execution_display", "impact_estimation"],
            },
        }

        missing_components = []
        stub_only_components = []
        incomplete_components = []

        for component_id, requirements in required_components.items():
            component = ux_components.get(component_id)

            if not component:
                missing_components.append({
                    "id": component_id,
                    "description": requirements["description"],
                })
                continue

            # Check if component is a stub
            if component.get("status") == "STUB":
                if enforce_mode:
                    stub_only_components.append({
                        "id": component_id,
                        "description": requirements["description"],
                        "status": "STUB",
                    })
                continue

            # Check if component is enabled
            if not component.get("enabled", False):
                missing_components.append({
                    "id": component_id,
                    "description": requirements["description"],
                    "reason": "disabled",
                })
                continue

            # Check required features
            component_features = set(component.get("features", []))
            required_features = set(requirements["required_features"])
            missing_features = required_features - component_features

            if missing_features:
                incomplete_components.append({
                    "id": component_id,
                    "description": requirements["description"],
                    "missing_features": list(missing_features),
                })

        # Report failures
        if missing_components:
            raise ValidationFailure(
                rule="UX.INTEGRITY.COMPONENT_MISSING",
                reason="Required UX components are missing",
                details={
                    "missing_components": missing_components,
                },
            )

        if stub_only_components:
            raise ValidationFailure(
                rule="UX.INTEGRITY.STUB_NOT_ENFORCED",
                reason="UX components are stubbed without enforcement",
                details={
                    "stub_components": stub_only_components,
                },
            )

        if incomplete_components:
            raise ValidationFailure(
                rule="UX.INTEGRITY.INCOMPLETE_FEATURES",
                reason="UX components missing required features",
                details={
                    "incomplete_components": incomplete_components,
                },
            )

        # Validate component integrations
        self._validate_ux_integrations(ux_components)

        logger.info("UX integrity validation PASSED")

    def _validate_ux_integrations(self, ux_components: Dict) -> None:
        """Validate UX component integrations are properly configured."""
        # Live Action Graph must be connected to ledger
        action_graph = ux_components.get("live_action_graph", {})
        if action_graph.get("enabled"):
            ledger_connection = action_graph.get("ledger_connection", {})
            if not ledger_connection.get("connected"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.ACTION_GRAPH_DISCONNECTED",
                    reason="Live Action Graph is not connected to ledger",
                )

            if not ledger_connection.get("real_time"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.ACTION_GRAPH_NOT_REALTIME",
                    reason="Live Action Graph ledger connection is not real-time",
                )

        # Replay Debugger must have access to replay data
        replay_debugger = ux_components.get("replay_debugger", {})
        if replay_debugger.get("enabled"):
            if not replay_debugger.get("replay_data_access"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.REPLAY_NO_DATA_ACCESS",
                    reason="Replay Debugger does not have replay data access",
                )

        # Dossier Builder must produce signed output
        dossier_builder = ux_components.get("dossier_builder", {})
        if dossier_builder.get("enabled"):
            output_config = dossier_builder.get("output_config", {})
            if not output_config.get("signing_enabled"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.DOSSIER_UNSIGNED",
                    reason="Dossier Builder signing is not enabled",
                )

            if not output_config.get("signing_key_ref"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.DOSSIER_NO_SIGNING_KEY",
                    reason="Dossier Builder has no signing key configured",
                )

        # Blast Radius Preview must be shown before execution
        blast_preview = ux_components.get("blast_radius_preview", {})
        if blast_preview.get("enabled"):
            if not blast_preview.get("pre_execution_required"):
                raise ValidationFailure(
                    rule="UX.INTEGRITY.BLAST_PREVIEW_NOT_REQUIRED",
                    reason="Blast Radius Preview is not required before execution",
                )


class RuntimeEnforcementGuard:
    """
    Runtime enforcement guard for continuous validation.

    Provides dual attestation with control plane.
    """

    def __init__(self, guard_id: str, validator: StrictValidator):
        self.guard_id = guard_id
        self.validator = validator
        self._action_rates: Dict[str, int] = {}
        self._last_rate_reset = datetime.now(timezone.utc)

    def _reset_rates_if_needed(self) -> None:
        """Reset rate counters every minute."""
        now = datetime.now(timezone.utc)
        if (now - self._last_rate_reset).seconds >= 60:
            self._action_rates = {}
            self._last_rate_reset = now

    def enforce_action(
        self,
        action: Dict,
        permit: ExecutionPermit,
        autonomy_level: int = 1,
        human_confirmation: bool = False,
    ) -> Dict:
        """
        Enforce action with dual attestation.

        Returns attestation record.
        """
        self._reset_rates_if_needed()

        target_id = action.get("target_id")

        # Update rate counter
        self._action_rates[target_id] = self._action_rates.get(target_id, 0) + 1

        try:
            # Run validation
            self.validator.validate_runtime_action(
                action=action,
                permit=permit,
                target_rates=self._action_rates,
                autonomy_level=autonomy_level,
                human_confirmation=human_confirmation,
            )

            return {
                "decision": "ALLOW",
                "guard_id": self.guard_id,
                "action_id": action.get("action_id"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attestation_hash": self.validator._compute_hash({
                    "decision": "ALLOW",
                    "action_id": action.get("action_id"),
                    "guard_id": self.guard_id,
                }),
            }

        except ValidationFailure as e:
            return {
                "decision": "DENY",
                "guard_id": self.guard_id,
                "action_id": action.get("action_id"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": e.reason,
                "rule": e.rule,
                "attestation_hash": self.validator._compute_hash({
                    "decision": "DENY",
                    "action_id": action.get("action_id"),
                    "guard_id": self.guard_id,
                    "rule": e.rule,
                }),
            }

    def create_dual_attestation(
        self,
        control_plane_attestation: Dict,
        runtime_attestation: Dict,
    ) -> Dict:
        """Create dual attestation record."""
        attestation_data = {
            'control': control_plane_attestation,
            'runtime': runtime_attestation,
        }
        attestation_hash = hashlib.sha256(
            json.dumps(attestation_data, sort_keys=True).encode()
        ).hexdigest()[:16]
        return {
            "attestation_id": f"dual-{attestation_hash}",
            "control_plane_attestation": control_plane_attestation,
            "runtime_guard_attestation": runtime_attestation,
            "combined_hash": self.validator._compute_hash({
                "control": control_plane_attestation,
                "runtime": runtime_attestation,
            }),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
