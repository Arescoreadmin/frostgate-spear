"""
Red Line Violation Tests.

Tests all 8 absolute red lines as defined in the blueprint:
1. No action outside mission ROE
2. No automated classification level modification
3. No persona override of ROE, safety, or policy
4. No cross-ring contamination
5. No destructive operations without AO signature
6. No scenario execution without hash match
7. No unsigned binaries
8. No un-attested artifacts
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from src.core.config import Config, ClassificationLevel
from src.core.exceptions import (
    ROEViolationError,
    MLSViolationError,
    RedLineViolationError,
    PersonaConstraintViolationError,
    ForensicIntegrityError,
)


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


class TestRedLine1_NoActionOutsideROE:
    """Red Line 1: No action outside mission ROE."""

    @pytest.mark.asyncio
    async def test_action_outside_allowed_assets_blocked(self, config):
        """Actions targeting assets outside ROE are blocked."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["web-server-01"],
                "disallowed_assets": ["critical-dc"],
                "allowed_networks": ["10.0.0.0/8"],
            }

            action = {
                "type": "reconnaissance",
                "target": {"asset": "critical-dc"},
                "tool": "nmap",
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
            assert "disallowed" in " ".join(result.violations).lower()
        finally:
            await roe_engine.stop()

    @pytest.mark.asyncio
    async def test_action_outside_allowed_networks_blocked(self, config):
        """Actions targeting networks outside ROE are blocked."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": [],
                "allowed_networks": ["10.0.0.0/8"],
            }

            action = {
                "type": "reconnaissance",
                "target": {"network": "192.168.1.0/24"},  # Not in allowed networks
                "tool": "nmap",
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
        finally:
            await roe_engine.stop()

    @pytest.mark.asyncio
    async def test_disallowed_tool_blocked(self, config):
        """Actions using disallowed tools are blocked."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["target-01"],
                "allowed_tools": ["nmap"],
                "disallowed_tools": ["metasploit"],
            }

            action = {
                "type": "exploitation",
                "target": {"asset": "target-01"},
                "tool": "metasploit",
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
        finally:
            await roe_engine.stop()

    @pytest.mark.asyncio
    async def test_action_outside_time_window_blocked(self, config):
        """Actions outside allowed time windows are blocked."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            # Set time window to yesterday
            yesterday = datetime.utcnow() - timedelta(days=1)
            roe = {
                "allowed_assets": ["target-01"],
                "time_window": {
                    "start": (yesterday - timedelta(hours=2)).isoformat(),
                    "end": (yesterday - timedelta(hours=1)).isoformat(),
                },
            }

            action = {
                "type": "reconnaissance",
                "target": {"asset": "target-01"},
                "tool": "nmap",
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
        finally:
            await roe_engine.stop()


class TestRedLine2_NoAutomatedClassificationChange:
    """Red Line 2: No automated classification level modification."""

    @pytest.mark.asyncio
    async def test_cannot_upgrade_classification_automatically(self, config):
        """Cannot automatically upgrade classification level."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Attempt to change classification level
            with pytest.raises(MLSViolationError):
                await mls.validate_classification_change(
                    current_level="UNCLASS",
                    new_level="SECRET",
                    authorized=False,
                )
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cannot_downgrade_classification_automatically(self, config):
        """Cannot automatically downgrade classification level."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Attempt to change classification level
            with pytest.raises(MLSViolationError):
                await mls.validate_classification_change(
                    current_level="SECRET",
                    new_level="UNCLASS",
                    authorized=False,
                )
        finally:
            await mls.stop()


class TestRedLine3_NoPersonaOverride:
    """Red Line 3: No persona override of ROE, safety, or policy."""

    def test_persona_cannot_override_roe(self):
        """Personas cannot override ROE constraints."""
        from src.personas import PersonaConstraints

        with pytest.raises(PersonaConstraintViolationError) as exc:
            PersonaConstraints(
                can_override_roe=True,  # This MUST fail
                can_override_safety=False,
                can_override_policy=False,
                respects_blast_radius=True,
                respects_scope=True,
            )

        assert "roe" in str(exc.value).lower()

    def test_persona_cannot_override_safety(self):
        """Personas cannot override safety constraints."""
        from src.personas import PersonaConstraints

        with pytest.raises(PersonaConstraintViolationError) as exc:
            PersonaConstraints(
                can_override_roe=False,
                can_override_safety=True,  # This MUST fail
                can_override_policy=False,
                respects_blast_radius=True,
                respects_scope=True,
            )

        assert "safety" in str(exc.value).lower()

    def test_persona_cannot_override_policy(self):
        """Personas cannot override policy constraints."""
        from src.personas import PersonaConstraints

        with pytest.raises(PersonaConstraintViolationError) as exc:
            PersonaConstraints(
                can_override_roe=False,
                can_override_safety=False,
                can_override_policy=True,  # This MUST fail
                respects_blast_radius=True,
                respects_scope=True,
            )

        assert "policy" in str(exc.value).lower()

    def test_persona_must_respect_blast_radius(self):
        """Personas must respect blast radius."""
        from src.personas import PersonaConstraints

        with pytest.raises(PersonaConstraintViolationError) as exc:
            PersonaConstraints(
                can_override_roe=False,
                can_override_safety=False,
                can_override_policy=False,
                respects_blast_radius=False,  # This MUST fail
                respects_scope=True,
            )

        assert "blast" in str(exc.value).lower()

    def test_persona_must_respect_scope(self):
        """Personas must respect scope boundaries."""
        from src.personas import PersonaConstraints

        with pytest.raises(PersonaConstraintViolationError) as exc:
            PersonaConstraints(
                can_override_roe=False,
                can_override_safety=False,
                can_override_policy=False,
                respects_blast_radius=True,
                respects_scope=False,  # This MUST fail
            )

        assert "scope" in str(exc.value).lower()


class TestRedLine4_NoCrossRingContamination:
    """Red Line 4: No cross-ring contamination."""

    @pytest.mark.asyncio
    async def test_no_read_up_allowed(self, config):
        """No read-up operations allowed (Bell-LaPadula)."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # UNCLASS cannot read SECRET
            with pytest.raises(MLSViolationError):
                await mls.validate_read("UNCLASS", "SECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_no_write_down_allowed(self, config):
        """No write-down operations allowed (Bell-LaPadula)."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # SECRET cannot write to UNCLASS
            with pytest.raises(MLSViolationError):
                await mls.validate_write("SECRET", "UNCLASS")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_no_gradient_sharing_across_rings(self, config):
        """No gradient sharing across classification rings."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            with pytest.raises(MLSViolationError):
                await fl.validate_gradient_transfer(
                    source_ring="SECRET",
                    target_ring="UNCLASS",
                    gradient_data={"weights": [0.1, 0.2]},
                )
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_no_model_sharing_across_rings_without_dp(self, config):
        """No model sharing across rings without differential privacy."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            with pytest.raises(MLSViolationError):
                await fl.validate_model_transfer(
                    source_ring="SECRET",
                    target_ring="CUI",
                    model_data={"model": "data"},
                    has_dp_applied=False,  # No DP
                )
        finally:
            await fl.stop()


class TestRedLine5_NoDestructiveWithoutAO:
    """Red Line 5: No destructive operations without AO signature."""

    @pytest.mark.asyncio
    async def test_destructive_ops_require_ao_approval(self, config):
        """Destructive operations require AO approval."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["target-01"],
                "destructive_ops_authorized": False,  # No AO approval
            }

            action = {
                "type": "impact",
                "target": {"asset": "target-01"},
                "destructive": True,
                "ao_signature": None,
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
            assert any("destructive" in v.lower() or "ao" in v.lower() for v in result.violations)
        finally:
            await roe_engine.stop()

    @pytest.mark.asyncio
    async def test_destructive_ops_allowed_with_ao_approval(self, config):
        """Destructive operations allowed with AO approval."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["target-01"],
                "destructive_ops_authorized": True,
            }

            action = {
                "type": "impact",
                "target": {"asset": "target-01"},
                "destructive": True,
            }

            result = await roe_engine.validate_action(action, roe)
            # Should not fail on destructive ops check
            assert "destructive" not in " ".join(result.violations).lower() if result.violations else True
        finally:
            await roe_engine.stop()


class TestRedLine6_NoScenarioWithoutHashMatch:
    """Red Line 6: No scenario execution without hash match."""

    @pytest.mark.asyncio
    async def test_scenario_hash_mismatch_blocked(self, config):
        """Scenario with hash mismatch is blocked."""
        from src.policy_interpreter import PolicyInterpreter

        interpreter = PolicyInterpreter(config)
        await interpreter.start()

        try:
            envelope = {
                "envelope_id": str(uuid4()),
                "version": "1.0.0",
                "mode": "simulation",
                "risk_tier": 1,
                "mission_type": "red_team",
                "classification_level": "UNCLASS",
                "scope_id": "test-scope",
                "scenario_hash": "sha256:incorrect_hash",
                "approvals": [],
                "valid_from": datetime.utcnow().isoformat(),
                "valid_to": (datetime.utcnow() + timedelta(days=1)).isoformat(),
                "roe": {},
            }

            scenario = {
                "name": "Test Scenario",
                "version": "1.0.0",
            }

            result = await interpreter.validate_scenario_hash(envelope, scenario)
            assert not result.valid
            assert "hash" in " ".join(result.errors).lower()
        finally:
            await interpreter.stop()


class TestRedLine7_NoUnsignedBinaries:
    """Red Line 7: No unsigned binaries."""

    @pytest.mark.asyncio
    async def test_unsigned_binary_blocked(self, config):
        """Unsigned binaries are blocked."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "binary",
                "name": "test-tool",
                "signature": None,  # Unsigned
            }

            result = await verifier.validate_artifact_signature(artifact)
            assert not result.valid
            assert "signature" in " ".join(result.errors).lower() or "unsigned" in " ".join(result.errors).lower()
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_signed_binary_allowed(self, config):
        """Properly signed binaries are allowed."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "binary",
                "name": "test-tool",
                "signature": {
                    "algorithm": "Ed25519",
                    "value": "dGVzdC1zaWduYXR1cmU=",
                    "signer_id": "frostgate-security-team",
                },
            }

            result = await verifier.validate_artifact_signature(artifact)
            assert result.valid or "untrusted" in " ".join(result.warnings).lower()
        finally:
            await verifier.stop()


class TestRedLine8_NoUnAttestedArtifacts:
    """Red Line 8: No un-attested artifacts."""

    @pytest.mark.asyncio
    async def test_unattested_artifact_blocked(self, config):
        """Un-attested artifacts are blocked."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "test-container",
                "attestation": None,  # No attestation
            }

            result = await verifier.validate_artifact_attestation(artifact)
            assert not result.valid
            assert "attestation" in " ".join(result.errors).lower()
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_attested_artifact_allowed(self, config):
        """Properly attested artifacts are allowed."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "test-container",
                "attestation": {
                    "hash": "sha256:abc123def456",
                    "provenance": {
                        "builder": "github-actions",
                        "build_id": "12345",
                        "source_repo": "org/repo",
                        "source_commit": "abc123",
                    },
                    "slsa_level": 3,
                },
            }

            result = await verifier.validate_artifact_attestation(artifact)
            assert result.valid
        finally:
            await verifier.stop()


class TestRedLineEnforcement:
    """Test that red line violations are properly logged and enforced."""

    @pytest.mark.asyncio
    async def test_red_line_violation_raises_critical_exception(self):
        """Red line violations raise critical exceptions."""
        from src.core.exceptions import RedLineViolationError

        error = RedLineViolationError(
            "Attempted action outside ROE",
            red_line="no_action_outside_roe",
            action="reconnaissance",
        )

        assert error.code == "RED_LINE_VIOLATION"
        assert error.details["severity"] == "CRITICAL"
        assert error.red_line == "no_action_outside_roe"

    @pytest.mark.asyncio
    async def test_red_line_violations_audited(self, config):
        """Red line violations are properly audited."""
        from src.audit import AuditSystem, AuditEventCategory

        audit = AuditSystem(config)
        await audit.start()

        try:
            # Log a red line event
            await audit.log_event(
                category=AuditEventCategory.RED_LINE_EVENT,
                action="attempted_roe_override",
                actor="test-persona",
                resource="mission-123",
                outcome="blocked",
                severity="emergency",
                details={
                    "red_line": "no_persona_override_roe",
                    "attempted_action": "modify_scope",
                },
            )

            # Verify event was logged
            events = await audit.get_events(category=AuditEventCategory.RED_LINE_EVENT)
            assert len(events) > 0
            assert events[-1]["category"] == AuditEventCategory.RED_LINE_EVENT.value
        finally:
            await audit.stop()
