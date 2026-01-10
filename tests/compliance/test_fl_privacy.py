"""
Federated Learning Differential Privacy Compliance Tests.

Tests DP configuration and enforcement per classification ring:
- UNCLASS: epsilon 1.0, delta 1e-5, min 3 participants
- CUI: epsilon 0.5, delta 1e-6, min 5 participants
- SECRET: epsilon 0.1, delta 1e-8, min 10 participants
- TOPSECRET: epsilon 0.01, delta 1e-10, min 20 participants
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.core.config import Config, ClassificationLevel
from src.core.exceptions import MLSViolationError


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


class TestDPConfiguration:
    """Tests for differential privacy configuration per ring."""

    @pytest.mark.asyncio
    async def test_unclass_dp_config(self, config):
        """UNCLASS ring has epsilon 1.0, delta 1e-5, min 3 participants."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            ring_config = fl.get_ring_config("UNCLASS")
            assert ring_config["epsilon"] <= 1.0
            assert ring_config["delta"] <= 1e-5
            assert ring_config["min_participants"] >= 3
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_cui_dp_config(self, config):
        """CUI ring has epsilon 0.5, delta 1e-6, min 5 participants."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            ring_config = fl.get_ring_config("CUI")
            assert ring_config["epsilon"] <= 0.5
            assert ring_config["delta"] <= 1e-6
            assert ring_config["min_participants"] >= 5
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_secret_dp_config(self, config):
        """SECRET ring has epsilon 0.1, delta 1e-8, min 10 participants."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            ring_config = fl.get_ring_config("SECRET")
            assert ring_config["epsilon"] <= 0.1
            assert ring_config["delta"] <= 1e-8
            assert ring_config["min_participants"] >= 10
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_topsecret_dp_config(self, config):
        """TOPSECRET ring has epsilon 0.01, delta 1e-10, min 20 participants."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            ring_config = fl.get_ring_config("TOPSECRET")
            assert ring_config["epsilon"] <= 0.01
            assert ring_config["delta"] <= 1e-10
            assert ring_config["min_participants"] >= 20
        finally:
            await fl.stop()


class TestDPEnforcement:
    """Tests for differential privacy enforcement."""

    @pytest.mark.asyncio
    async def test_epsilon_budget_enforced(self, config):
        """Epsilon budget is enforced."""
        from src.fl import FLController, DPBudgetExceededError

        fl = FLController(config)
        await fl.start()

        try:
            # Attempt to exceed epsilon budget
            with pytest.raises(DPBudgetExceededError):
                await fl.apply_noise(
                    ring="UNCLASS",
                    model_id="test-model",
                    requested_epsilon=2.0,  # Exceeds UNCLASS limit of 1.0
                )
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_min_participants_enforced(self, config):
        """Minimum participants requirement is enforced."""
        from src.fl import FLController, InsufficientParticipantsError

        fl = FLController(config)
        await fl.start()

        try:
            # Attempt aggregation with insufficient participants
            with pytest.raises(InsufficientParticipantsError):
                await fl.aggregate_round(
                    ring="CUI",
                    model_id="test-model",
                    participants=["client-1", "client-2"],  # Only 2, need 5 for CUI
                )
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_noise_calibration_per_ring(self, config):
        """Noise is properly calibrated per ring."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Higher rings should have more noise
            noise_unclass = await fl.calculate_noise_scale("UNCLASS")
            noise_secret = await fl.calculate_noise_scale("SECRET")

            # SECRET should have more noise (lower epsilon = more noise)
            assert noise_secret > noise_unclass
        finally:
            await fl.stop()


class TestSecureAggregation:
    """Tests for secure aggregation in FL."""

    @pytest.mark.asyncio
    async def test_secure_aggregation_required_for_cui(self, config):
        """Secure aggregation is required for CUI and above."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            ring_config = fl.get_ring_config("CUI")
            assert ring_config.get("secure_aggregation_required", False)
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_gradients_encrypted_in_transit(self, config):
        """Gradients are encrypted during transmission."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            gradient = {"layer1": [0.1, 0.2, 0.3]}
            encrypted = await fl.encrypt_gradient(gradient, "SECRET")

            # Encrypted gradient should not be readable
            assert encrypted != gradient
            assert "ciphertext" in encrypted or "encrypted" in str(type(encrypted)).lower()
        finally:
            await fl.stop()


class TestGradientIsolation:
    """Tests for gradient isolation across rings."""

    @pytest.mark.asyncio
    async def test_no_raw_gradient_sharing(self, config):
        """No raw gradient sharing across rings."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            with pytest.raises(MLSViolationError):
                await fl.share_gradient(
                    source_ring="SECRET",
                    target_ring="CUI",
                    gradient={"layer1": [0.1, 0.2]},
                    dp_applied=False,
                )
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_dp_required_for_cross_ring_model_sharing(self, config):
        """DP is required for any cross-ring model sharing."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Without DP, cross-ring sharing should fail
            with pytest.raises(MLSViolationError):
                await fl.validate_model_transfer(
                    source_ring="SECRET",
                    target_ring="CUI",
                    model_data={"weights": [0.1, 0.2]},
                    has_dp_applied=False,
                )

            # With DP, should be allowed (if other conditions met)
            result = await fl.validate_model_transfer(
                source_ring="SECRET",
                target_ring="CUI",
                model_data={"weights": [0.1, 0.2]},
                has_dp_applied=True,
            )
            # May require additional approvals but should not fail on DP check
        finally:
            await fl.stop()


class TestPrivacyBudgetTracking:
    """Tests for privacy budget tracking."""

    @pytest.mark.asyncio
    async def test_privacy_budget_tracked(self, config):
        """Privacy budget is tracked per model and ring."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Use some budget
            await fl.apply_noise(
                ring="UNCLASS",
                model_id="test-model",
                requested_epsilon=0.5,
            )

            # Check remaining budget
            remaining = await fl.get_remaining_budget("UNCLASS", "test-model")
            assert remaining <= 0.5  # Started with 1.0, used 0.5
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_budget_audit_trail(self, config):
        """Privacy budget usage has audit trail."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Use budget
            await fl.apply_noise(
                ring="UNCLASS",
                model_id="test-model",
                requested_epsilon=0.3,
            )

            # Check audit trail
            audit = await fl.get_budget_audit("UNCLASS", "test-model")
            assert len(audit) > 0
            assert audit[-1]["epsilon_used"] == 0.3
        finally:
            await fl.stop()


class TestFLRingGateCompliance:
    """Tests for FL Ring Gate compliance (Gate 7)."""

    @pytest.mark.asyncio
    async def test_fl_ring_gate_validates_no_contamination(self, config):
        """FL Ring Gate validates no cross-ring gradient contamination."""
        from src.governance import GovernanceManager

        governance = GovernanceManager(config)
        await governance.start()

        try:
            metrics = {
                "cross_ring_gradient_transfers": 0,
                "dp_bounds_intact": True,
                "secure_aggregation_verified": True,
            }

            result = await governance.validate_fl_ring_gate(metrics, "CUI")
            assert result.passed
        finally:
            await governance.stop()

    @pytest.mark.asyncio
    async def test_fl_ring_gate_fails_on_contamination(self, config):
        """FL Ring Gate fails when contamination detected."""
        from src.governance import GovernanceManager

        governance = GovernanceManager(config)
        await governance.start()

        try:
            metrics = {
                "cross_ring_gradient_transfers": 5,  # Contamination!
                "dp_bounds_intact": True,
                "secure_aggregation_verified": True,
            }

            result = await governance.validate_fl_ring_gate(metrics, "CUI")
            assert not result.passed
            assert any("contamination" in c.lower() or "cross" in c.lower() for c in result.failed_criteria)
        finally:
            await governance.stop()

    @pytest.mark.asyncio
    async def test_fl_ring_gate_fails_on_dp_violation(self, config):
        """FL Ring Gate fails when DP bounds violated."""
        from src.governance import GovernanceManager

        governance = GovernanceManager(config)
        await governance.start()

        try:
            metrics = {
                "cross_ring_gradient_transfers": 0,
                "dp_bounds_intact": False,  # DP violated!
                "secure_aggregation_verified": True,
            }

            result = await governance.validate_fl_ring_gate(metrics, "CUI")
            assert not result.passed
            assert any("dp" in c.lower() or "privacy" in c.lower() for c in result.failed_criteria)
        finally:
            await governance.stop()


class TestClippingNormEnforcement:
    """Tests for gradient clipping norm enforcement."""

    @pytest.mark.asyncio
    async def test_gradient_clipping_applied(self, config):
        """Gradient clipping is applied before aggregation."""
        from src.fl import FLController
        import numpy as np

        fl = FLController(config)
        await fl.start()

        try:
            # Large gradient that should be clipped
            large_gradient = {"layer1": [100.0, 200.0, 300.0]}

            clipped = await fl.clip_gradient(large_gradient, max_norm=1.0)

            # Clipped gradient should have norm <= max_norm
            values = clipped["layer1"]
            norm = sum(v**2 for v in values) ** 0.5
            assert norm <= 1.0 + 1e-6  # Small tolerance for floating point
        finally:
            await fl.stop()


class TestModelProvenanceTracking:
    """Tests for FL model provenance tracking."""

    @pytest.mark.asyncio
    async def test_model_provenance_tracked(self, config):
        """Model provenance is tracked for audit."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            # Create model
            model_id = await fl.create_model(
                ring="UNCLASS",
                name="test-model",
                architecture={"layers": 3},
            )

            # Get provenance
            provenance = await fl.get_model_provenance(model_id)
            assert provenance["ring"] == "UNCLASS"
            assert provenance["created_at"] is not None
            assert provenance["training_rounds"] == 0
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_training_history_recorded(self, config):
        """Training history is recorded."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            model_id = "test-model"

            # Record training round
            await fl.record_training_round(
                ring="UNCLASS",
                model_id=model_id,
                round_number=1,
                participants=["client-1", "client-2", "client-3"],
                epsilon_used=0.3,
            )

            # Get history
            history = await fl.get_training_history(model_id)
            assert len(history) > 0
            assert history[-1]["round"] == 1
            assert history[-1]["epsilon_used"] == 0.3
        finally:
            await fl.stop()
