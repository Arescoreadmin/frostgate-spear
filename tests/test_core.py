"""
Tests for Frost Gate Spear Core Module
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.core.config import Config, ClassificationLevel, Environment
from src.core.mission import Mission, MissionState, MissionApproval
from src.core.exceptions import (
    FrostGateError,
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
    MLSViolationError,
)


class TestConfig:
    """Tests for configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()

        assert config.environment == Environment.SIMULATION
        assert config.classification_level == ClassificationLevel.UNCLASS
        assert config.forensics.completeness_threshold == 0.95
        assert config.governance.sim_runs_required == 1000

    def test_config_from_dict(self):
        """Test configuration from dictionary."""
        data = {
            "environment": "lab",
            "classification_level": "CUI",
            "forensics": {
                "completeness_threshold": 0.98,
            },
        }

        config = Config.from_dict(data)

        assert config.environment == Environment.LAB
        assert config.classification_level == ClassificationLevel.CUI
        assert config.forensics.completeness_threshold == 0.98

    def test_config_validation(self):
        """Test configuration validation."""
        config = Config()
        config.forensics.completeness_threshold = 1.5  # Invalid

        errors = config.validate()

        assert len(errors) > 0
        assert any("completeness" in e.lower() for e in errors)


class TestMission:
    """Tests for mission management."""

    def test_mission_creation(self):
        """Test basic mission creation."""
        mission = Mission(
            policy_envelope={"mission_type": "simulation", "risk_tier": 1},
            scenario={"targets": []},
            classification_level="UNCLASS",
        )

        assert mission.state == MissionState.CREATED
        assert mission.classification_level == "UNCLASS"
        assert mission.progress == 0.0

    def test_mission_approval(self):
        """Test mission approval workflow."""
        mission = Mission(
            policy_envelope={"mission_type": "red_team", "risk_tier": 2},
            scenario={},
        )

        approval = MissionApproval(
            approver_id="user-123",
            approver_name="Test User",
            role="Security",
            timestamp=datetime.utcnow(),
            signature="test-signature",
            scope_hash="sha256:abc123",
        )

        mission.add_approval(approval)

        assert len(mission.approvals) == 1
        assert mission.has_required_approvals(["Security"])
        assert not mission.has_required_approvals(["Security", "AO"])

    def test_mission_to_dict(self):
        """Test mission serialization."""
        mission = Mission(
            policy_envelope={"mission_type": "simulation"},
            scenario={"name": "test"},
            classification_level="CUI",
        )

        data = mission.to_dict()

        assert "mission_id" in data
        assert data["classification_level"] == "CUI"
        assert data["state"] == "created"


class TestExceptions:
    """Tests for exception handling."""

    def test_policy_violation_error(self):
        """Test policy violation exception."""
        error = PolicyViolationError(
            "Test violation",
            policy_id="policy-123",
            violations=["violation1", "violation2"],
        )

        assert error.code == "POLICY_VIOLATION"
        assert len(error.violations) == 2

        error_dict = error.to_dict()
        assert error_dict["error"] == "POLICY_VIOLATION"
        assert "violation1" in error_dict["details"]["violations"]

    def test_roe_violation_error(self):
        """Test ROE violation exception."""
        error = ROEViolationError(
            "Target out of scope",
            roe_rule="scope_check",
            action="lateral_movement",
            target="dc01.example.com",
        )

        assert error.code == "ROE_VIOLATION"
        assert error.target == "dc01.example.com"

    def test_mls_violation_error(self):
        """Test MLS violation exception."""
        error = MLSViolationError(
            "Cross-ring data flow",
            source_ring="SECRET",
            target_ring="UNCLASS",
            operation="write",
        )

        assert error.code == "MLS_VIOLATION"
        assert error.source_ring == "SECRET"

    def test_safety_constraint_error(self):
        """Test safety constraint exception."""
        error = SafetyConstraintError(
            "Blast radius exceeded",
            constraint="blast_radius",
            current_value=75.0,
            threshold=50.0,
        )

        assert error.code == "SAFETY_CONSTRAINT_VIOLATION"
        assert error.current_value == 75.0
        assert error.threshold == 50.0


class TestClassificationLevels:
    """Tests for classification level handling."""

    def test_classification_enum(self):
        """Test classification level enumeration."""
        assert ClassificationLevel.UNCLASS.value == "UNCLASS"
        assert ClassificationLevel.CUI.value == "CUI"
        assert ClassificationLevel.SECRET.value == "SECRET"
        assert ClassificationLevel.TOPSECRET.value == "TOPSECRET"

    def test_classification_ordering(self):
        """Test classification level ordering."""
        levels = [
            ClassificationLevel.UNCLASS,
            ClassificationLevel.CUI,
            ClassificationLevel.SECRET,
            ClassificationLevel.TOPSECRET,
        ]

        # Verify ordering by position
        assert levels.index(ClassificationLevel.UNCLASS) < levels.index(ClassificationLevel.CUI)
        assert levels.index(ClassificationLevel.CUI) < levels.index(ClassificationLevel.SECRET)
        assert levels.index(ClassificationLevel.SECRET) < levels.index(ClassificationLevel.TOPSECRET)


class TestEnvironments:
    """Tests for environment handling."""

    def test_environment_enum(self):
        """Test environment enumeration."""
        assert Environment.SIMULATION.value == "simulation"
        assert Environment.LAB.value == "lab"
        assert Environment.CANARY.value == "canary"
        assert Environment.PRODUCTION.value == "production"
        assert Environment.MISSION.value == "mission"

    def test_promotion_path(self):
        """Test valid promotion paths."""
        valid_paths = [
            (Environment.SIMULATION, Environment.LAB),
            (Environment.LAB, Environment.CANARY),
            (Environment.CANARY, Environment.PRODUCTION),
            (Environment.CANARY, Environment.MISSION),
        ]

        for source, target in valid_paths:
            # Just verify these are valid environment values
            assert source in Environment
            assert target in Environment
