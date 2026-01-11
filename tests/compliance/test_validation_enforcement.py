"""
Frost Gate Spear - Validation Enforcement Tests

Tests for STRICT validation enforcement. No soft failures, warnings, or overrides.
If ANY required check fails, execution MUST NOT proceed.
"""

import hashlib
import json
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from src.validation import (
    StrictValidator,
    ValidationFailure,
    ApprovalRecord,
    ExecutionPermit,
    CredentialMode,
    ExecutionMode,
    RuntimeEnforcementGuard,
)


def compute_hash(data):
    """Compute SHA-256 hash."""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True, separators=(',', ':'))
    if isinstance(data, str):
        data = data.encode('utf-8')
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def create_valid_scope():
    """Create a valid canonical scope."""
    scope = {
        "scope_id": str(uuid4()),
        "version": "1.0.0",
        "assets": [
            {
                "asset_id": "HOST-123456789",
                "asset_type": "HOST",
                "inventory_ref": "cmdb://host/123456789",
            }
        ],
        "boundaries": {
            "networks": [
                {
                    "cidr": "10.0.0.0/8",
                    "description": "Internal network",
                }
            ],
            "domains": [
                {
                    "domain": "example.com",
                    "scope_type": "EXACT",
                }
            ],
        },
        "exclusions": [],
        "time_window": {
            "start": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "end": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(),
            "timezone": "UTC",
        },
        "environment": "LAB",
        "authorization_ref": {
            "ref_id": "AUTH-001",
            "type": "INTERNAL_APPROVAL",
        },
        "contact_on_call": {
            "primary": {
                "name": "John Doe",
                "email": "john@example.com",
                "phone": "+1-555-0100",
            },
            "escalation_path": [
                {"level": 1, "contact": "John Doe", "sla_minutes": 15},
            ],
        },
    }
    # Compute scope hash
    scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
    scope["scope_hash"] = compute_hash(scope_for_hash)
    return scope


def create_valid_campaign():
    """Create a valid campaign."""
    return {
        "campaign_id": str(uuid4()),
        "mode": "SIM",
        "risk_tier": 1,
        "credential_mode": "UNAUTHENTICATED",
        "entrypoints_required": 1,
        "diversity_requirements": {},
        "classification_level": "UNCLASS",
        "scope_ref": {
            "scope_id": str(uuid4()),
            "scope_hash": "sha256:" + "a" * 64,
        },
    }


def create_valid_permit(campaign):
    """Create a valid execution permit."""
    now = datetime.now(timezone.utc)
    return ExecutionPermit(
        permit_id=str(uuid4()),
        campaign_id=campaign["campaign_id"],
        tenant_id=str(uuid4()),
        mode=ExecutionMode.SIM,
        risk_tier=1,
        credential_mode=CredentialMode.UNAUTHENTICATED,
        tool_allowlist=[
            {"tool_id": "nmap", "version": "7.94", "certification": "SIM_SAFE"},
        ],
        target_allowlist=[
            {"target_id": "HOST-123456789", "target_type": "HOST", "max_actions_per_minute": 60},
        ],
        entrypoint_allowlist=[
            {"entrypoint_id": "ep-001", "region": "us-east-1", "network_zone": "PUBLIC"},
        ],
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        nonce="test-nonce-" + str(uuid4()),
        jti=str(uuid4()),
        cr_ref={"cr_id": "N/A", "approved_at": now.isoformat()},
        sig={"algorithm": "ES256", "value": "test", "key_id": "key-001"},
    )


def create_valid_approval(scope_hash, campaign_hash, role="Security"):
    """Create a valid approval record."""
    now = datetime.now(timezone.utc)
    return ApprovalRecord(
        approver_id="approver-001",
        role=role,
        timestamp=now,
        expires_at=now + timedelta(hours=24),
        scope_hash=scope_hash,
        campaign_hash=campaign_hash,
        signature="test-signature",
    )


class TestCanonicalScopeValidation:
    """Tests for canonical scope validation."""

    def test_valid_scope_passes(self):
        """Valid scope should pass validation."""
        validator = StrictValidator()
        scope = create_valid_scope()
        validator.validate_canonical_scope(scope)  # Should not raise

    def test_missing_scope_id_fails(self):
        """Missing scope_id should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        del scope["scope_id"]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.SCOPE_ID"

    def test_invalid_scope_id_format_fails(self):
        """Invalid scope_id format should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["scope_id"] = "not-a-uuid"

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.SCOPE_ID_FORMAT"

    def test_free_text_asset_id_fails(self):
        """Free text asset IDs should fail (not strongly typed)."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["assets"][0]["asset_id"] = "my server"  # Free text, not pattern

        # Recompute hash
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        scope["scope_hash"] = compute_hash(scope_for_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.ASSET_ID_FORMAT"

    def test_missing_boundaries_fails(self):
        """Missing boundaries should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["boundaries"] = {}

        # Recompute hash
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        scope["scope_hash"] = compute_hash(scope_for_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert "BOUNDARIES" in exc.value.rule

    def test_missing_time_window_fails(self):
        """Missing time window should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        del scope["time_window"]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert "TIME_WINDOW" in exc.value.rule

    def test_time_window_exceeds_limit_fails(self):
        """Time window exceeding policy limits should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        now = datetime.now(timezone.utc)
        scope["time_window"] = {
            "start": now.isoformat(),
            "end": (now + timedelta(hours=100)).isoformat(),  # Exceeds 72h limit
            "timezone": "UTC",
        }

        # Recompute hash
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        scope["scope_hash"] = compute_hash(scope_for_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.TIME_WINDOW_DURATION"

    def test_invalid_environment_fails(self):
        """Invalid environment should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["environment"] = "INVALID"

        # Recompute hash
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        scope["scope_hash"] = compute_hash(scope_for_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.ENVIRONMENT"

    def test_prod_without_auth_ref_fails(self):
        """PROD environment without authorization_ref should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["environment"] = "PROD"
        scope["authorization_ref"] = {}

        # Recompute hash
        scope_for_hash = {k: v for k, v in scope.items() if k != "scope_hash"}
        scope["scope_hash"] = compute_hash(scope_for_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert "AUTHORIZATION_REF" in exc.value.rule

    def test_scope_hash_mismatch_fails(self):
        """Scope hash mismatch should fail."""
        validator = StrictValidator()
        scope = create_valid_scope()
        scope["scope_hash"] = "sha256:" + "0" * 64  # Wrong hash

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_canonical_scope(scope)
        assert exc.value.rule == "PREFLIGHT.SCOPE.SCOPE_HASH_MISMATCH"


class TestCredentialModeValidation:
    """Tests for credential mode validation."""

    def test_unauthenticated_mode_passes(self):
        """UNAUTHENTICATED mode without vault refs should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        validator.validate_credential_mode(campaign)

    def test_authenticated_without_vault_refs_fails(self):
        """AUTHENTICATED mode without vault refs should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["credential_mode"] = "AUTHENTICATED"

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_credential_mode(campaign)
        assert exc.value.rule == "PREFLIGHT.CREDENTIAL.VAULT_REFS"

    def test_authenticated_with_raw_secret_fails(self):
        """AUTHENTICATED mode with raw secrets should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["credential_mode"] = "AUTHENTICATED"
        campaign["credential_refs"] = [
            {
                "vault_ref": "raw_password_value",  # Raw secret, not vault ref
            }
        ]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_credential_mode(campaign)
        assert exc.value.rule == "PREFLIGHT.CREDENTIAL.RAW_SECRET"

    def test_authenticated_with_vault_ref_passes(self):
        """AUTHENTICATED mode with proper vault refs should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["credential_mode"] = "AUTHENTICATED"
        campaign["credential_refs"] = [
            {
                "vault_ref": "vault:secret/data/campaign/creds",
            }
        ]
        validator.validate_credential_mode(campaign)

    def test_invalid_credential_mode_fails(self):
        """Invalid credential mode should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["credential_mode"] = "INVALID"

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_credential_mode(campaign)
        assert exc.value.rule == "PREFLIGHT.CREDENTIAL.MODE"


class TestGovernanceValidation:
    """Tests for governance and approval validation."""

    def test_valid_approvals_pass(self):
        """Valid approvals should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        scope_hash = campaign["scope_ref"]["scope_hash"]
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        approvals = [
            create_valid_approval(scope_hash, campaign_hash, "Security"),
        ]

        validator.validate_governance(campaign, approvals, "executor-001")

    def test_missing_required_approval_fails(self):
        """Missing required approvals should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["risk_tier"] = 2  # Requires Security + Product
        scope_hash = campaign["scope_ref"]["scope_hash"]
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        approvals = [
            create_valid_approval(scope_hash, campaign_hash, "Security"),
            # Missing Product approval
        ]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_governance(campaign, approvals, "executor-001")
        assert exc.value.rule == "GOVERNANCE.APPROVAL.MISSING_ROLES"
        assert "Product" in str(exc.value.details.get("missing"))

    def test_expired_approval_fails(self):
        """Expired approvals should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        scope_hash = campaign["scope_ref"]["scope_hash"]
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        expired = ApprovalRecord(
            approver_id="approver-001",
            role="Security",
            timestamp=datetime.now(timezone.utc) - timedelta(days=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # Expired
            scope_hash=scope_hash,
            campaign_hash=campaign_hash,
            signature="test",
        )

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_governance(campaign, [expired], "executor-001")
        assert exc.value.rule == "GOVERNANCE.APPROVAL.EXPIRED"

    def test_scope_hash_mismatch_fails(self):
        """Approval with wrong scope_hash should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        wrong_scope = create_valid_approval("sha256:" + "x" * 64, campaign_hash)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_governance(campaign, [wrong_scope], "executor-001")
        assert exc.value.rule == "GOVERNANCE.APPROVAL.SCOPE_HASH_MISMATCH"

    def test_separation_of_duties_fails(self):
        """Executor being approver for high-risk LIVE should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["mode"] = "LIVE_GUARDED"
        campaign["risk_tier"] = 3
        campaign["cr_ref"] = {"cr_id": "CR-001", "approved_at": datetime.now(timezone.utc).isoformat()}

        scope_hash = campaign["scope_ref"]["scope_hash"]
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        # Campaign hash must include cr_ref
        campaign["cr_ref"]["campaign_hash"] = campaign_hash

        approvals = [
            ApprovalRecord(
                approver_id="executor-001",  # Same as executor
                role="Security",
                timestamp=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                scope_hash=scope_hash,
                campaign_hash=campaign_hash,
                signature="test",
            ),
            ApprovalRecord(
                approver_id="approver-002",
                role="Product",
                timestamp=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                scope_hash=scope_hash,
                campaign_hash=campaign_hash,
                signature="test",
            ),
            ApprovalRecord(
                approver_id="approver-003",
                role="AO",
                timestamp=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                scope_hash=scope_hash,
                campaign_hash=campaign_hash,
                signature="test",
            ),
        ]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_governance(campaign, approvals, "executor-001")
        assert exc.value.rule == "GOVERNANCE.SEPARATION_OF_DUTIES"

    def test_non_sim_without_cr_fails(self):
        """Non-SIM campaign without CR should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["mode"] = "SHADOW"  # Non-SIM

        scope_hash = campaign["scope_ref"]["scope_hash"]
        campaign_hash = compute_hash({
            k: v for k, v in campaign.items()
            if k not in ("approvals", "preflight")
        })

        approvals = [create_valid_approval(scope_hash, campaign_hash)]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_governance(campaign, approvals, "executor-001")
        assert exc.value.rule == "GOVERNANCE.CR.MISSING"


class TestExecutionPermitValidation:
    """Tests for execution permit validation."""

    def test_valid_permit_passes(self):
        """Valid permit should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        validator.validate_execution_permit(permit, campaign)

    def test_expired_permit_fails(self):
        """Expired permit should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        # Make permit expired
        permit.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_execution_permit(permit, campaign)
        assert exc.value.rule == "PERMIT.EXPIRED"

    def test_reused_nonce_fails(self):
        """Reused nonce should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        # First use should pass
        validator.validate_execution_permit(permit, campaign)

        # Create new permit with same nonce
        permit2 = create_valid_permit(campaign)
        permit2.nonce = permit.nonce  # Reuse nonce

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_execution_permit(permit2, campaign)
        assert exc.value.rule == "PERMIT.NONCE.REUSED"

    def test_campaign_id_mismatch_fails(self):
        """Permit with wrong campaign_id should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)
        permit.campaign_id = str(uuid4())  # Different campaign

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_execution_permit(permit, campaign)
        assert exc.value.rule == "PERMIT.CAMPAIGN_MISMATCH"

    def test_mode_mismatch_fails(self):
        """Permit with wrong mode should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)
        permit.mode = ExecutionMode.LIVE_GUARDED  # Different mode

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_execution_permit(permit, campaign)
        assert exc.value.rule == "PERMIT.MODE_MISMATCH"


class TestRuntimeEnforcement:
    """Tests for runtime enforcement."""

    def test_allowed_action_passes(self):
        """Allowed action should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "nmap",
            "target_id": "HOST-123456789",
        }

        validator.validate_runtime_action(
            action=action,
            permit=permit,
            target_rates={"HOST-123456789": 0},
            autonomy_level=1,
            human_confirmation=False,
        )

    def test_unauthorized_tool_fails(self):
        """Action with unauthorized tool should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "metasploit",  # Not in allowlist
            "target_id": "HOST-123456789",
        }

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_runtime_action(
                action=action,
                permit=permit,
                target_rates={},
                autonomy_level=1,
                human_confirmation=False,
            )
        assert exc.value.rule == "RUNTIME.TOOL_NOT_ALLOWED"

    def test_unauthorized_target_fails(self):
        """Action on unauthorized target should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "nmap",
            "target_id": "HOST-999999999",  # Not in allowlist
        }

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_runtime_action(
                action=action,
                permit=permit,
                target_rates={},
                autonomy_level=1,
                human_confirmation=False,
            )
        assert exc.value.rule == "RUNTIME.TARGET_NOT_ALLOWED"

    def test_rate_limit_exceeded_fails(self):
        """Exceeding rate limit should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "nmap",
            "target_id": "HOST-123456789",
        }

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_runtime_action(
                action=action,
                permit=permit,
                target_rates={"HOST-123456789": 100},  # Exceeds 60/min
                autonomy_level=1,
                human_confirmation=False,
            )
        assert exc.value.rule == "RUNTIME.RATE_LIMIT_EXCEEDED"

    def test_human_confirmation_required_fails(self):
        """Action requiring human confirmation without it should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "nmap",
            "target_id": "HOST-123456789",
            "requires_human_confirmation": True,
        }

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_runtime_action(
                action=action,
                permit=permit,
                target_rates={},
                autonomy_level=1,
                human_confirmation=False,  # No confirmation
            )
        assert exc.value.rule == "RUNTIME.HUMAN_CONFIRMATION_REQUIRED"


class TestLedgerIntegrity:
    """Tests for ledger integrity validation."""

    def create_ledger_entries(self, count=3):
        """Create valid ledger entries."""
        entries = []
        campaign_id = str(uuid4())

        for i in range(count):
            payload = {"action": f"action_{i}"}
            timestamp = datetime.now(timezone.utc).isoformat()

            entry = {
                "entry_id": f"entry-{i}",
                "campaign_id": campaign_id,
                "sequence_number": i + 1,
                "event_type": "ACTION_STARTED",
                "timestamp": timestamp,
                "payload": payload,
                "previous_hash": entries[-1]["entry_hash"] if entries else None,
            }

            # Compute entry hash
            hash_content = {
                "entry_id": entry["entry_id"],
                "campaign_id": entry["campaign_id"],
                "sequence_number": entry["sequence_number"],
                "event_type": entry["event_type"],
                "timestamp": entry["timestamp"],
                "payload_hash": compute_hash(payload),
                "previous_hash": entry["previous_hash"],
            }
            entry["entry_hash"] = compute_hash(hash_content)
            entries.append(entry)

        return entries

    def test_valid_ledger_passes(self):
        """Valid ledger should pass."""
        validator = StrictValidator()
        entries = self.create_ledger_entries(5)
        validator.validate_ledger_integrity(entries)

    def test_empty_ledger_fails(self):
        """Empty ledger should fail."""
        validator = StrictValidator()

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_ledger_integrity([])
        assert exc.value.rule == "LEDGER.EMPTY"

    def test_first_entry_with_previous_hash_fails(self):
        """First entry with previous_hash should fail."""
        validator = StrictValidator()
        entries = self.create_ledger_entries(3)
        entries[0]["previous_hash"] = "sha256:" + "a" * 64

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_ledger_integrity(entries)
        assert exc.value.rule == "LEDGER.FIRST_ENTRY_LINK"

    def test_sequence_gap_fails(self):
        """Sequence gap should fail."""
        validator = StrictValidator()
        entries = self.create_ledger_entries(3)
        entries[1]["sequence_number"] = 5  # Gap

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_ledger_integrity(entries)
        assert exc.value.rule == "LEDGER.SEQUENCE_GAP"

    def test_chain_break_fails(self):
        """Chain break (wrong previous_hash) should fail."""
        validator = StrictValidator()
        entries = self.create_ledger_entries(3)
        entries[1]["previous_hash"] = "sha256:" + "x" * 64  # Wrong hash

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_ledger_integrity(entries)
        assert exc.value.rule == "LEDGER.CHAIN_BREAK"


class TestReplayDeterminism:
    """Tests for replay determinism validation."""

    def create_valid_manifest(self):
        """Create valid replay manifest."""
        return {
            "determinism_config": {
                "rng_seeding": {
                    "enabled": True,
                    "seed_strategy": "RECORDED_SEED",
                    "master_seed": "test-seed-12345",
                },
                "time_virtualization": {
                    "enabled": True,
                    "strategy": "RECORDED_TIMESTAMPS",
                },
            },
            "snapshot_refs": {
                "environment": [{"snapshot_id": "env-1", "hash": "sha256:abc"}],
                "tool_versions": [{"snapshot_id": "tool-1", "hash": "sha256:def"}],
            },
            "nondeterministic_inputs": [],
            "has_external_inputs": False,
        }

    def test_valid_replay_passes(self):
        """Valid replay should pass."""
        validator = StrictValidator()
        manifest = self.create_valid_manifest()
        results = {
            "total_events": 100,
            "matching_events": 98,  # 98% determinism
        }

        validator.validate_replay_determinism(manifest, results)

    def test_missing_rng_seed_fails(self):
        """Missing RNG seed should fail."""
        validator = StrictValidator()
        manifest = self.create_valid_manifest()
        manifest["determinism_config"]["rng_seeding"]["master_seed"] = None

        results = {"total_events": 100, "matching_events": 100}

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_replay_determinism(manifest, results)
        assert exc.value.rule == "REPLAY.RNG.NO_SEED"

    def test_disabled_time_virtualization_fails(self):
        """Disabled time virtualization should fail."""
        validator = StrictValidator()
        manifest = self.create_valid_manifest()
        manifest["determinism_config"]["time_virtualization"]["enabled"] = False

        results = {"total_events": 100, "matching_events": 100}

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_replay_determinism(manifest, results)
        assert exc.value.rule == "REPLAY.TIME.NOT_ENABLED"

    def test_low_determinism_score_fails(self):
        """Low determinism score should fail."""
        validator = StrictValidator()
        manifest = self.create_valid_manifest()
        results = {
            "total_events": 100,
            "matching_events": 80,  # 80% - below 95% threshold
        }

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_replay_determinism(manifest, results)
        assert exc.value.rule == "REPLAY.DETERMINISM.LOW"


class TestFinalIntegrity:
    """Tests for final integrity validation."""

    def test_valid_final_integrity_passes(self):
        """Valid final integrity should pass."""
        validator = StrictValidator()

        bundle_content = {"item": "test"}
        evidence_bundles = [{
            "bundle_id": "bundle-1",
            **bundle_content,
        }]
        evidence_bundles[0]["bundle_hash"] = compute_hash(bundle_content)

        daily_anchors = [
            {"merkle_root": "sha256:" + "a" * 64, "signature": "sig-1"},
        ]

        witness_checkpoints = []

        redaction_report = {"secrets_removed": True}

        validator.validate_final_integrity(
            evidence_bundles=evidence_bundles,
            daily_anchors=daily_anchors,
            witness_checkpoints=witness_checkpoints,
            redaction_report=redaction_report,
            forensic_completeness=0.98,
        )

    def test_missing_redaction_report_fails(self):
        """Missing redaction report should fail."""
        validator = StrictValidator()

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_final_integrity(
                evidence_bundles=[],
                daily_anchors=[{"merkle_root": "x", "signature": "y"}],
                witness_checkpoints=[],
                redaction_report=None,
                forensic_completeness=0.98,
            )
        assert exc.value.rule == "FINAL.REDACTION.MISSING"

    def test_incomplete_secrets_removal_fails(self):
        """Incomplete secrets removal should fail."""
        validator = StrictValidator()

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_final_integrity(
                evidence_bundles=[],
                daily_anchors=[{"merkle_root": "x", "signature": "y"}],
                witness_checkpoints=[],
                redaction_report={"secrets_removed": False},
                forensic_completeness=0.98,
            )
        assert exc.value.rule == "FINAL.REDACTION.INCOMPLETE"

    def test_low_forensic_completeness_fails(self):
        """Low forensic completeness should fail."""
        validator = StrictValidator()

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_final_integrity(
                evidence_bundles=[],
                daily_anchors=[{"merkle_root": "x", "signature": "y"}],
                witness_checkpoints=[],
                redaction_report={"secrets_removed": True},
                forensic_completeness=0.80,  # Below 95%
            )
        assert exc.value.rule == "FINAL.FORENSICS.INCOMPLETE"


class TestRuntimeEnforcementGuard:
    """Tests for RuntimeEnforcementGuard."""

    def test_allowed_action_returns_allow(self):
        """Allowed action should return ALLOW decision."""
        validator = StrictValidator()
        guard = RuntimeEnforcementGuard("guard-001", validator)

        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "nmap",
            "target_id": "HOST-123456789",
        }

        result = guard.enforce_action(action, permit)
        assert result["decision"] == "ALLOW"
        assert result["guard_id"] == "guard-001"

    def test_denied_action_returns_deny(self):
        """Denied action should return DENY decision."""
        validator = StrictValidator()
        guard = RuntimeEnforcementGuard("guard-001", validator)

        campaign = create_valid_campaign()
        permit = create_valid_permit(campaign)

        action = {
            "action_id": str(uuid4()),
            "tool_id": "not-allowed-tool",
            "target_id": "HOST-123456789",
        }

        result = guard.enforce_action(action, permit)
        assert result["decision"] == "DENY"
        assert "TOOL_NOT_ALLOWED" in result["rule"]

    def test_dual_attestation_created(self):
        """Dual attestation should be created correctly."""
        validator = StrictValidator()
        guard = RuntimeEnforcementGuard("guard-001", validator)

        control_attestation = {"decision": "ALLOW", "source": "control-plane"}
        runtime_attestation = {"decision": "ALLOW", "source": "runtime-guard"}

        dual = guard.create_dual_attestation(control_attestation, runtime_attestation)

        assert "attestation_id" in dual
        assert dual["control_plane_attestation"] == control_attestation
        assert dual["runtime_guard_attestation"] == runtime_attestation
        assert "combined_hash" in dual


class TestEntrypointFeasibility:
    """Tests for entrypoint feasibility validation."""

    def test_valid_entrypoints_pass(self):
        """Valid entrypoints should pass."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["entrypoints_required"] = 2
        campaign["diversity_requirements"] = {
            "require_different_regions": True,
        }

        entrypoints = [
            {"entrypoint_id": "ep-1", "region": "us-east-1", "network_zone": "PUBLIC", "egress_asn_class": "DATACENTER", "egress_ip_pool_ref": "pool-1"},
            {"entrypoint_id": "ep-2", "region": "us-west-2", "network_zone": "PUBLIC", "egress_asn_class": "DATACENTER", "egress_ip_pool_ref": "pool-2"},
        ]

        pools = {"pool-1": 10, "pool-2": 10}

        validator.validate_entrypoint_feasibility(campaign, entrypoints, pools)

    def test_insufficient_entrypoints_fails(self):
        """Insufficient entrypoints should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["entrypoints_required"] = 5

        entrypoints = [
            {"entrypoint_id": "ep-1", "region": "us-east-1"},
            {"entrypoint_id": "ep-2", "region": "us-west-2"},
        ]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_entrypoint_feasibility(campaign, entrypoints, {})
        assert exc.value.rule == "PREFLIGHT.ENTRYPOINT.INSUFFICIENT"

    def test_exhausted_egress_pool_fails(self):
        """Exhausted egress pool should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()

        entrypoints = [
            {"entrypoint_id": "ep-1", "region": "us-east-1", "egress_ip_pool_ref": "pool-1"},
        ]

        pools = {"pool-1": 0}  # Exhausted

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_entrypoint_feasibility(campaign, entrypoints, pools)
        assert exc.value.rule == "PREFLIGHT.ENTRYPOINT.EGRESS_EXHAUSTED"

    def test_diversity_requirement_fails(self):
        """Failing diversity requirement should fail."""
        validator = StrictValidator()
        campaign = create_valid_campaign()
        campaign["entrypoints_required"] = 2
        campaign["diversity_requirements"] = {
            "require_different_regions": True,
        }

        entrypoints = [
            {"entrypoint_id": "ep-1", "region": "us-east-1", "network_zone": "PUBLIC", "egress_asn_class": "DATACENTER"},
            {"entrypoint_id": "ep-2", "region": "us-east-1", "network_zone": "PUBLIC", "egress_asn_class": "DATACENTER"},  # Same region
        ]

        with pytest.raises(ValidationFailure) as exc:
            validator.validate_entrypoint_feasibility(campaign, entrypoints, {})
        assert exc.value.rule == "PREFLIGHT.ENTRYPOINT.DIVERSITY_REGION"
