"""
Comprehensive Compliance Tests for Governance Gates.

Tests all 7 gates as defined in the blueprint:
1. Security Gate - Red team review, gov security review, tool catalog, MLS isolation
2. Safety Gate - 1000 SIM runs, 0 policy violations, deception FP rate < 5%
3. Forensic Gate - Completeness >= 95%, replay success >= 95%, Merkle lineage valid
4. Impact Gate - TIE scoring within envelope, zero-impact mode for critical systems
5. Performance Gate - Costs < budget, latency SLOs green, alert footprint within ROE
6. Ops Gate - SOC replay successful, Blue Box explanation, AO sign-off
7. FL Ring Gate - No cross-ring gradient contamination, DP bounds intact
"""

import asyncio
import pytest
from datetime import datetime
from uuid import uuid4

from src.core.config import Config, ClassificationLevel
from src.governance import GovernanceManager
from src.core.exceptions import PromotionGateError


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


@pytest.fixture
def governance_manager(config):
    """Create governance manager instance."""
    return GovernanceManager(config)


class TestSecurityGate:
    """Tests for Security Gate (Gate 1)."""

    @pytest.mark.asyncio
    async def test_security_gate_requires_red_team_review(self, governance_manager):
        """Security gate requires red team review."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": False,
                "tool_catalog_validated": True,
                "mls_isolation_validated": True,
            }
            result = await governance_manager.validate_security_gate(artifact, "UNCLASS")
            assert not result.passed
            assert any("red team" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_security_gate_requires_gov_review_for_secret(self, governance_manager):
        """Security gate requires government security review for SECRET/TOPSECRET."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "gov_security_review": False,
                "tool_catalog_validated": True,
                "mls_isolation_validated": True,
            }
            result = await governance_manager.validate_security_gate(artifact, "SECRET")
            assert not result.passed
            assert any("government" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_security_gate_requires_tool_catalog_validation(self, governance_manager):
        """Security gate requires tool catalog validation."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "tool_catalog_validated": False,
                "mls_isolation_validated": True,
            }
            result = await governance_manager.validate_security_gate(artifact, "UNCLASS")
            assert not result.passed
            assert any("tool catalog" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_security_gate_requires_mls_isolation(self, governance_manager):
        """Security gate requires MLS isolation validation."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "tool_catalog_validated": True,
                "mls_isolation_validated": False,
            }
            result = await governance_manager.validate_security_gate(artifact, "UNCLASS")
            assert not result.passed
            assert any("mls" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_security_gate_passes_all_criteria(self, governance_manager):
        """Security gate passes when all criteria are met."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "gov_security_review": True,
                "tool_catalog_validated": True,
                "mls_isolation_validated": True,
            }
            result = await governance_manager.validate_security_gate(artifact, "SECRET")
            assert result.passed
            assert len(result.failed_criteria) == 0
        finally:
            await governance_manager.stop()


class TestSafetyGate:
    """Tests for Safety Gate (Gate 2)."""

    @pytest.mark.asyncio
    async def test_safety_gate_requires_1000_sim_runs(self, governance_manager):
        """Safety gate requires 1000 simulation runs."""
        await governance_manager.start()
        try:
            metrics = {
                "sim_runs": 500,
                "policy_violations": 0,
                "deception_fp_rate": 0.01,
            }
            result = await governance_manager.validate_safety_gate(metrics, "UNCLASS")
            assert not result.passed
            assert any("simulation" in c.lower() or "runs" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_safety_gate_requires_zero_policy_violations(self, governance_manager):
        """Safety gate requires zero policy violations."""
        await governance_manager.start()
        try:
            metrics = {
                "sim_runs": 1000,
                "policy_violations": 5,
                "deception_fp_rate": 0.01,
            }
            result = await governance_manager.validate_safety_gate(metrics, "UNCLASS")
            assert not result.passed
            assert any("violation" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_safety_gate_requires_low_deception_fp_rate(self, governance_manager):
        """Safety gate requires deception false positive rate < 5%."""
        await governance_manager.start()
        try:
            metrics = {
                "sim_runs": 1000,
                "policy_violations": 0,
                "deception_fp_rate": 0.10,  # 10% - too high
            }
            result = await governance_manager.validate_safety_gate(metrics, "UNCLASS")
            assert not result.passed
            assert any("deception" in c.lower() or "fp" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_safety_gate_passes_all_criteria(self, governance_manager):
        """Safety gate passes when all criteria are met."""
        await governance_manager.start()
        try:
            metrics = {
                "sim_runs": 1000,
                "policy_violations": 0,
                "deception_fp_rate": 0.03,
            }
            result = await governance_manager.validate_safety_gate(metrics, "UNCLASS")
            assert result.passed
            assert len(result.failed_criteria) == 0
        finally:
            await governance_manager.stop()


class TestForensicGate:
    """Tests for Forensic Gate (Gate 3)."""

    @pytest.mark.asyncio
    async def test_forensic_gate_requires_completeness_95(self, governance_manager):
        """Forensic gate requires >= 95% completeness."""
        await governance_manager.start()
        try:
            metrics = {
                "forensic_completeness": 0.90,
                "replay_success": 0.98,
                "merkle_lineage_valid": True,
            }
            result = await governance_manager.validate_forensic_gate(metrics)
            assert not result.passed
            assert any("completeness" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_forensic_gate_requires_replay_success_95(self, governance_manager):
        """Forensic gate requires >= 95% replay success."""
        await governance_manager.start()
        try:
            metrics = {
                "forensic_completeness": 0.98,
                "replay_success": 0.85,
                "merkle_lineage_valid": True,
            }
            result = await governance_manager.validate_forensic_gate(metrics)
            assert not result.passed
            assert any("replay" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_forensic_gate_requires_valid_merkle_lineage(self, governance_manager):
        """Forensic gate requires valid Merkle lineage."""
        await governance_manager.start()
        try:
            metrics = {
                "forensic_completeness": 0.98,
                "replay_success": 0.98,
                "merkle_lineage_valid": False,
            }
            result = await governance_manager.validate_forensic_gate(metrics)
            assert not result.passed
            assert any("merkle" in c.lower() for c in result.failed_criteria)
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_forensic_gate_passes_all_criteria(self, governance_manager):
        """Forensic gate passes when all criteria are met."""
        await governance_manager.start()
        try:
            metrics = {
                "forensic_completeness": 0.98,
                "replay_success": 0.97,
                "merkle_lineage_valid": True,
            }
            result = await governance_manager.validate_forensic_gate(metrics)
            assert result.passed
            assert len(result.failed_criteria) == 0
        finally:
            await governance_manager.stop()


class TestImpactGate:
    """Tests for Impact Gate (Gate 4)."""

    @pytest.mark.asyncio
    async def test_impact_gate_validates_tie_scoring(self, config):
        """Impact gate validates TIE scoring within envelope."""
        from src.tie import TargetImpactEstimator

        tie = TargetImpactEstimator(config)
        await tie.start()

        try:
            action = {
                "type": "reconnaissance",
                "target": {"type": "web_server"},
            }
            estimate = await tie.estimate_action_impact(action)
            assert estimate.score >= 0
            assert estimate.score <= 100
        finally:
            await tie.stop()

    @pytest.mark.asyncio
    async def test_impact_gate_enforces_blast_radius_cap(self, config):
        """Impact gate enforces blast radius cap."""
        from src.tie import TargetImpactEstimator

        tie = TargetImpactEstimator(config)
        await tie.start()

        try:
            action = {
                "type": "impact",
                "target": {"type": "domain_controller"},
                "destructive": True,
            }
            context = {"blast_radius_cap": 10}
            estimate = await tie.estimate_action_impact(action, context)
            # High-impact action should be flagged
            assert estimate.exceeds_blast_radius or estimate.score > 10
        finally:
            await tie.stop()


class TestPerformanceGate:
    """Tests for Performance Gate (Gate 5)."""

    @pytest.mark.asyncio
    async def test_performance_gate_checks_budget(self, governance_manager):
        """Performance gate checks budget constraints."""
        await governance_manager.start()
        try:
            # Record budget usage near limit
            await governance_manager.record_budget_usage(
                tenant_id="test-tenant",
                ring="UNCLASS",
                cost_usd=950,
            )

            # Should be under 1000 USD limit
            from src.core.mission import Mission

            class MockMission:
                policy_envelope = {
                    "tenant_id": "test-tenant",
                    "budget_cap": {"cost_usd": 1000},
                }
                classification_level = "UNCLASS"

            mission = MockMission()
            result = await governance_manager.check_budget(mission)
            assert result
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_performance_gate_blocks_exceeded_budget(self, governance_manager):
        """Performance gate blocks when budget is exceeded."""
        await governance_manager.start()
        try:
            # Record budget usage over limit
            await governance_manager.record_budget_usage(
                tenant_id="over-budget-tenant",
                ring="UNCLASS",
                cost_usd=1500,
            )

            class MockMission:
                policy_envelope = {
                    "tenant_id": "over-budget-tenant",
                    "budget_cap": {"cost_usd": 1000},
                }
                classification_level = "UNCLASS"

            from src.core.exceptions import BudgetExceededError

            mission = MockMission()
            with pytest.raises(BudgetExceededError):
                await governance_manager.check_budget(mission)
        finally:
            await governance_manager.stop()


class TestOpsGate:
    """Tests for Ops Gate (Gate 6)."""

    @pytest.mark.asyncio
    async def test_ops_gate_requires_ao_signoff_for_classified(self, governance_manager):
        """Ops gate requires AO sign-off for classified missions."""
        await governance_manager.start()
        try:
            from src.core.mission import Mission, MissionApproval

            class MockMission:
                approvals = []
                policy_envelope = {"mode": "production", "risk_tier": 3}
                classification_level = "SECRET"

            mission = MockMission()
            from src.core.exceptions import ApprovalRequiredError

            with pytest.raises(ApprovalRequiredError) as exc:
                await governance_manager.validate_approvals(mission)

            assert "AO" in str(exc.value) or any("ao" in r.lower() for r in exc.value.missing_roles)
        finally:
            await governance_manager.stop()


class TestFLRingGate:
    """Tests for FL Ring Gate (Gate 7)."""

    @pytest.mark.asyncio
    async def test_fl_ring_gate_enforces_dp_bounds(self, config):
        """FL ring gate enforces differential privacy bounds."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Verify DP configuration is loaded
            ring_config = fl.get_ring_config("UNCLASS")
            assert ring_config is not None
            assert ring_config.get("epsilon", 0) <= 1.0  # UNCLASS epsilon should be <= 1.0
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_fl_ring_gate_prevents_cross_ring_gradients(self, config):
        """FL ring gate prevents cross-ring gradient sharing."""
        from src.fl import FLController
        from src.core.exceptions import MLSViolationError

        fl = FLController(config)
        await fl.start()

        try:
            # Attempt to share gradients across rings
            with pytest.raises(MLSViolationError):
                await fl.validate_gradient_transfer(
                    source_ring="SECRET",
                    target_ring="UNCLASS",
                    gradient_data={"test": "data"},
                )
        finally:
            await fl.stop()


class TestPromotionPath:
    """Tests for Promotion Path (SIM -> LAB -> CANARY -> PRODUCTION)."""

    @pytest.mark.asyncio
    async def test_valid_promotion_path_sim_to_lab(self, governance_manager):
        """Test valid promotion from SIM to LAB."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "tool_catalog_validated": True,
                "mls_isolation_validated": True,
                "metrics": {
                    "sim_runs": 1000,
                    "policy_violations": 0,
                    "deception_fp_rate": 0.01,
                    "forensic_completeness": 0.98,
                    "replay_success": 0.98,
                    "merkle_lineage_valid": True,
                },
            }
            result = await governance_manager.validate_promotion(
                artifact, "simulation", "lab", "UNCLASS"
            )
            assert result
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_invalid_promotion_path_blocked(self, governance_manager):
        """Test invalid promotion paths are blocked."""
        await governance_manager.start()
        try:
            artifact = {"metrics": {}}

            with pytest.raises(PromotionGateError):
                # Skip from SIM directly to PRODUCTION - not allowed
                await governance_manager.validate_promotion(
                    artifact, "simulation", "production", "UNCLASS"
                )
        finally:
            await governance_manager.stop()

    @pytest.mark.asyncio
    async def test_promotion_requires_all_gates(self, governance_manager):
        """Test promotion requires all gates to pass."""
        await governance_manager.start()
        try:
            artifact = {
                "red_team_review": True,
                "tool_catalog_validated": True,
                "mls_isolation_validated": True,
                "metrics": {
                    "sim_runs": 500,  # Insufficient
                    "policy_violations": 0,
                    "deception_fp_rate": 0.01,
                    "forensic_completeness": 0.98,
                    "replay_success": 0.98,
                    "merkle_lineage_valid": True,
                },
            }

            with pytest.raises(PromotionGateError):
                await governance_manager.validate_promotion(
                    artifact, "simulation", "lab", "UNCLASS"
                )
        finally:
            await governance_manager.stop()


class TestGateHistory:
    """Tests for gate validation history tracking."""

    @pytest.mark.asyncio
    async def test_gate_results_are_stored(self, governance_manager):
        """Gate results are stored for audit."""
        await governance_manager.start()
        try:
            metrics = {
                "sim_runs": 1000,
                "policy_violations": 0,
                "deception_fp_rate": 0.01,
            }
            await governance_manager.validate_safety_gate(metrics, "UNCLASS")

            history = governance_manager.get_gate_history("safety")
            assert len(history) > 0
            assert history[-1].gate_name == "safety"
            assert history[-1].passed
        finally:
            await governance_manager.stop()
