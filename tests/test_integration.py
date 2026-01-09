"""
Integration tests for Frost Gate Spear.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from src.core import FrostGateSpear, Config
from src.core.mission import Mission, MissionState, MissionApproval
from src.core.exceptions import (
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
)


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


@pytest.fixture
def valid_policy_envelope():
    """Create valid policy envelope for testing."""
    return {
        "envelope_id": str(uuid4()),
        "version": "1.0.0",
        "mode": "simulation",
        "risk_tier": 1,
        "mission_type": "red_team",
        "classification_level": "UNCLASS",
        "scope_id": "test-scope-001",
        "approvals": [
            {
                "approver_id": "test-approver",
                "approver_name": "Test Approver",
                "role": "Security",
                "timestamp": datetime.utcnow().isoformat(),
                "signature": "test-signature",
                "scope_hash": "sha256:test",
                "valid": True,
            }
        ],
        "valid_from": datetime.utcnow().isoformat(),
        "valid_to": (datetime.utcnow() + timedelta(days=30)).isoformat(),
        "roe": {
            "allowed_assets": ["web-server-01", "db-server-01"],
            "allowed_networks": ["10.0.0.0/8"],
            "allowed_tool_categories": ["reconnaissance", "vulnerability_scan"],
            "blast_radius_cap": 50,
            "alert_footprint_cap": 10,
        },
        "budget_cap": {
            "compute_hours": 100,
            "api_calls": 10000,
            "cost_usd": 1000,
        },
    }


@pytest.fixture
def valid_scenario():
    """Create valid scenario for testing."""
    return {
        "name": "Test Scenario",
        "version": "1.0.0",
        "objective": "Test objective",
        "targets": [
            {
                "name": "web-server-01",
                "type": "web_server",
                "network": "10.0.1.0/24",
            }
        ],
        "kill_chain": ["reconnaissance", "initial_access"],
    }


class TestEngineIntegration:
    """Integration tests for the main engine."""

    @pytest.mark.asyncio
    async def test_engine_lifecycle(self, config):
        """Test engine start and stop."""
        engine = FrostGateSpear(config)

        await engine.start()
        assert engine.state.value == "ready"

        await engine.stop()

    @pytest.mark.asyncio
    async def test_create_mission(self, config, valid_policy_envelope, valid_scenario):
        """Test mission creation."""
        engine = FrostGateSpear(config)
        await engine.start()

        try:
            mission = await engine.create_mission(
                policy_envelope=valid_policy_envelope,
                scenario=valid_scenario,
            )

            assert mission.mission_id is not None
            assert mission.state == MissionState.CREATED
            assert mission.classification_level == "UNCLASS"

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_mission_with_invalid_envelope(self, config, valid_scenario):
        """Test mission creation with invalid envelope."""
        engine = FrostGateSpear(config)
        await engine.start()

        try:
            invalid_envelope = {"mode": "simulation"}  # Missing required fields

            with pytest.raises(PolicyViolationError):
                await engine.create_mission(
                    policy_envelope=invalid_envelope,
                    scenario=valid_scenario,
                )

        finally:
            await engine.stop()


class TestROEEnforcement:
    """Tests for ROE enforcement."""

    @pytest.mark.asyncio
    async def test_roe_allows_valid_action(self, config):
        """Test ROE allows valid actions."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["target-01"],
                "allowed_networks": ["10.0.0.0/8"],
                "allowed_tools": ["nmap"],
            }

            action = {
                "type": "reconnaissance",
                "target": {"asset": "target-01", "network": "10.0.1.0/24"},
                "tool": "nmap",
            }

            result = await roe_engine.validate_action(action, roe)
            assert result.valid

        finally:
            await roe_engine.stop()

    @pytest.mark.asyncio
    async def test_roe_blocks_disallowed_target(self, config):
        """Test ROE blocks disallowed targets."""
        from src.roe_engine import ROEEngine

        roe_engine = ROEEngine(config)
        await roe_engine.start()

        try:
            roe = {
                "allowed_assets": ["target-01"],
                "disallowed_assets": ["critical-system"],
                "allowed_networks": ["10.0.0.0/8"],
            }

            action = {
                "type": "reconnaissance",
                "target": {"asset": "critical-system"},
                "tool": "nmap",
            }

            result = await roe_engine.validate_action(action, roe)
            assert not result.valid
            assert any("disallowed" in v.lower() for v in result.violations)

        finally:
            await roe_engine.stop()


class TestMLSEnforcement:
    """Tests for Multi-Level Security enforcement."""

    @pytest.mark.asyncio
    async def test_mls_read_up_blocked(self, config):
        """Test MLS blocks read-up operations."""
        from src.mls import MLSManager

        mls_manager = MLSManager(config)
        await mls_manager.start()

        try:
            # UNCLASS trying to read SECRET should fail
            from src.core.exceptions import MLSViolationError

            with pytest.raises(MLSViolationError):
                await mls_manager.validate_read("UNCLASS", "SECRET")

        finally:
            await mls_manager.stop()

    @pytest.mark.asyncio
    async def test_mls_same_ring_allowed(self, config):
        """Test MLS allows same-ring operations."""
        from src.mls import MLSManager

        mls_manager = MLSManager(config)
        await mls_manager.start()

        try:
            result = await mls_manager.validate_read("CUI", "CUI")
            assert result

        finally:
            await mls_manager.stop()


class TestPolicyInterpreter:
    """Tests for policy interpretation."""

    @pytest.mark.asyncio
    async def test_validate_valid_envelope(self, config, valid_policy_envelope):
        """Test validation of valid envelope."""
        from src.policy_interpreter import PolicyInterpreter

        interpreter = PolicyInterpreter(config)
        await interpreter.start()

        try:
            result = await interpreter.validate_envelope(valid_policy_envelope)
            assert result.valid
            assert result.envelope_hash.startswith("sha256:")

        finally:
            await interpreter.stop()

    @pytest.mark.asyncio
    async def test_interpret_constraints(self, config, valid_policy_envelope):
        """Test constraint interpretation."""
        from src.policy_interpreter import PolicyInterpreter

        interpreter = PolicyInterpreter(config)
        await interpreter.start()

        try:
            await interpreter.validate_envelope(valid_policy_envelope)
            constraints = await interpreter.interpret_constraints(valid_policy_envelope)

            assert constraints["classification_level"] == "UNCLASS"
            assert constraints["risk_tier"] == 1
            assert constraints["roe"]["blast_radius_cap"] == 50

        finally:
            await interpreter.stop()


class TestTIE:
    """Tests for Target Impact Estimator."""

    @pytest.mark.asyncio
    async def test_estimate_action_impact(self, config):
        """Test action impact estimation."""
        from src.tie import TargetImpactEstimator

        tie = TargetImpactEstimator(config)
        await tie.start()

        try:
            action = {
                "type": "exploitation",
                "target": {"type": "domain_controller"},
            }

            estimate = await tie.estimate_action_impact(action)

            assert estimate.score > 0
            assert estimate.score <= 100
            assert estimate.confidence > 0

        finally:
            await tie.stop()

    @pytest.mark.asyncio
    async def test_blast_radius_enforcement(self, config):
        """Test blast radius cap enforcement."""
        from src.tie import TargetImpactEstimator
        from src.core.exceptions import BlastRadiusExceededError

        tie = TargetImpactEstimator(config)
        await tie.start()

        try:
            action = {
                "type": "impact",
                "target": {"type": "domain_controller"},
                "destructive": True,
            }

            context = {"blast_radius_cap": 10}  # Very low cap

            estimate = await tie.estimate_action_impact(action, context)

            # High-impact action should exceed low cap
            assert estimate.exceeds_blast_radius

        finally:
            await tie.stop()


class TestForensics:
    """Tests for forensics subsystem."""

    @pytest.mark.asyncio
    async def test_forensic_logging(self, config, valid_policy_envelope, valid_scenario):
        """Test forensic record creation."""
        from src.forensics import ForensicsManager
        from src.core.mission import Mission, ActionResult
        from uuid import uuid4

        forensics = ForensicsManager(config)
        await forensics.start()

        try:
            mission = Mission(
                policy_envelope=valid_policy_envelope,
                scenario=valid_scenario,
            )

            action_result = ActionResult(
                action_id=uuid4(),
                action_type="reconnaissance",
                target="test-target",
                status="success",
                timestamp=datetime.utcnow(),
                duration_ms=100,
            )

            record = await forensics.log_action(mission, action_result)

            assert record.record_id is not None
            assert record.mission_id == mission.mission_id
            assert record.hash != ""

        finally:
            await forensics.stop()

    @pytest.mark.asyncio
    async def test_forensic_completeness(self, config, valid_policy_envelope, valid_scenario):
        """Test forensic completeness calculation."""
        from src.forensics import ForensicsManager
        from src.core.mission import Mission, ActionResult
        from uuid import uuid4

        forensics = ForensicsManager(config)
        await forensics.start()

        try:
            mission = Mission(
                policy_envelope=valid_policy_envelope,
                scenario=valid_scenario,
            )
            mission.actions_completed = 5

            # Log some actions
            for i in range(5):
                result = ActionResult(
                    action_id=uuid4(),
                    action_type="reconnaissance",
                    target=f"target-{i}",
                    status="success",
                    timestamp=datetime.utcnow(),
                    duration_ms=100,
                )
                await forensics.log_action(mission, result)

            completeness = await forensics.get_completeness(mission)
            assert completeness > 0

        finally:
            await forensics.stop()


class TestGovernance:
    """Tests for governance subsystem."""

    @pytest.mark.asyncio
    async def test_approval_validation(self, config, valid_policy_envelope, valid_scenario):
        """Test approval validation."""
        from src.governance import GovernanceManager

        governance = GovernanceManager(config)
        await governance.start()

        try:
            mission = Mission(
                policy_envelope=valid_policy_envelope,
                scenario=valid_scenario,
            )

            # Add required approval
            approval = MissionApproval(
                approver_id="test",
                approver_name="Test",
                role="Security",
                timestamp=datetime.utcnow(),
                signature="test",
                scope_hash="test",
            )
            mission.add_approval(approval)

            # Should pass for simulation mode with Security approval
            result = await governance.validate_approvals(mission)
            assert result

        finally:
            await governance.stop()

    @pytest.mark.asyncio
    async def test_gate_validation(self, config):
        """Test governance gate validation."""
        from src.governance import GovernanceManager

        governance = GovernanceManager(config)
        await governance.start()

        try:
            metrics = {
                "sim_runs": 1000,
                "policy_violations": 0,
                "deception_fp_rate": 0.01,
            }

            result = await governance.validate_safety_gate(metrics, "UNCLASS")

            assert result.passed
            assert result.gate_name == "safety"

        finally:
            await governance.stop()


class TestToolCatalog:
    """Tests for tool catalog."""

    def test_get_tool(self, config):
        """Test tool retrieval."""
        from src.tools import ToolCatalog

        catalog = ToolCatalog(config)

        tool = catalog.get_tool("nmap")
        assert tool is not None
        assert tool.name == "Nmap"
        assert tool.risk_tier.value == 1

    def test_list_tools_by_category(self, config):
        """Test tool listing by category."""
        from src.tools import ToolCatalog, ToolCategory

        catalog = ToolCatalog(config)

        recon_tools = catalog.list_tools(category=ToolCategory.RECONNAISSANCE)
        assert len(recon_tools) > 0
        assert all(t.category == ToolCategory.RECONNAISSANCE for t in recon_tools)

    def test_validate_tool_access(self, config):
        """Test tool access validation."""
        from src.tools import ToolCatalog

        catalog = ToolCatalog(config)

        # Should allow access to low-risk tool
        allowed, reason = catalog.validate_tool_access(
            "nmap",
            classification="UNCLASS",
            approved_roles=[],
        )
        assert allowed

        # Should require approval for high-risk tool
        allowed, reason = catalog.validate_tool_access(
            "metasploit",
            classification="UNCLASS",
            approved_roles=[],
        )
        assert not allowed
        assert "approval" in reason.lower()
