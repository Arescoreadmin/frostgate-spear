"""
MLS (Multi-Level Security) Cross-Ring Contamination Tests.

Tests Bell-LaPadula enforcement and ring isolation:
- No read-up operations
- No write-down operations
- Ring isolation for data
- Ring isolation for gradients
- Classification level enforcement
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.core.config import Config, ClassificationLevel
from src.core.exceptions import MLSViolationError, CrossRingContaminationError


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


class TestBellLaPadulaEnforcement:
    """Tests for Bell-LaPadula enforcement."""

    @pytest.mark.asyncio
    async def test_unclass_cannot_read_cui(self, config):
        """UNCLASS cannot read CUI data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("UNCLASS", "CUI")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_unclass_cannot_read_secret(self, config):
        """UNCLASS cannot read SECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("UNCLASS", "SECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_unclass_cannot_read_topsecret(self, config):
        """UNCLASS cannot read TOPSECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("UNCLASS", "TOPSECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cui_cannot_read_secret(self, config):
        """CUI cannot read SECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("CUI", "SECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cui_cannot_read_topsecret(self, config):
        """CUI cannot read TOPSECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("CUI", "TOPSECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_secret_cannot_read_topsecret(self, config):
        """SECRET cannot read TOPSECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_read("SECRET", "TOPSECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_topsecret_cannot_write_secret(self, config):
        """TOPSECRET cannot write to SECRET."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_write("TOPSECRET", "SECRET")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_secret_cannot_write_cui(self, config):
        """SECRET cannot write to CUI."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_write("SECRET", "CUI")
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cui_cannot_write_unclass(self, config):
        """CUI cannot write to UNCLASS."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            with pytest.raises(MLSViolationError):
                await mls.validate_write("CUI", "UNCLASS")
        finally:
            await mls.stop()


class TestSameRingOperations:
    """Tests for same-ring operations."""

    @pytest.mark.asyncio
    async def test_same_ring_read_allowed(self, config):
        """Same-ring read operations are allowed."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            for ring in ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]:
                result = await mls.validate_read(ring, ring)
                assert result
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_same_ring_write_allowed(self, config):
        """Same-ring write operations are allowed."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            for ring in ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]:
                result = await mls.validate_write(ring, ring)
                assert result
        finally:
            await mls.stop()


class TestReadDownOperations:
    """Tests for read-down operations (allowed in Bell-LaPadula)."""

    @pytest.mark.asyncio
    async def test_topsecret_can_read_secret(self, config):
        """TOPSECRET can read SECRET data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.validate_read("TOPSECRET", "SECRET")
            assert result
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_secret_can_read_cui(self, config):
        """SECRET can read CUI data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.validate_read("SECRET", "CUI")
            assert result
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cui_can_read_unclass(self, config):
        """CUI can read UNCLASS data."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.validate_read("CUI", "UNCLASS")
            assert result
        finally:
            await mls.stop()


class TestWriteUpOperations:
    """Tests for write-up operations (allowed in Bell-LaPadula)."""

    @pytest.mark.asyncio
    async def test_unclass_can_write_cui(self, config):
        """UNCLASS can write to CUI."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.validate_write("UNCLASS", "CUI")
            assert result
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cui_can_write_secret(self, config):
        """CUI can write to SECRET."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.validate_write("CUI", "SECRET")
            assert result
        finally:
            await mls.stop()


class TestRingIsolation:
    """Tests for ring isolation."""

    @pytest.mark.asyncio
    async def test_ring_isolation_enforced(self, config):
        """Ring isolation is enforced for operations."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Create isolated contexts
            ctx_unclass = await mls.create_ring_context("UNCLASS")
            ctx_secret = await mls.create_ring_context("SECRET")

            assert ctx_unclass.ring == "UNCLASS"
            assert ctx_secret.ring == "SECRET"
            assert ctx_unclass.isolation_id != ctx_secret.isolation_id
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_data_tagged_with_classification(self, config):
        """Data is properly tagged with classification level."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            data = {"sensitive": "information"}
            tagged = await mls.tag_data(data, "SECRET")

            assert tagged["_classification"] == "SECRET"
            assert tagged["_tagged_at"] is not None
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_cannot_access_data_from_higher_ring(self, config):
        """Cannot access data tagged with higher classification."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            data = {"sensitive": "information"}
            tagged = await mls.tag_data(data, "SECRET")

            with pytest.raises(MLSViolationError):
                await mls.access_data(tagged, accessor_ring="UNCLASS")
        finally:
            await mls.stop()


class TestGradientIsolation:
    """Tests for FL gradient isolation."""

    @pytest.mark.asyncio
    async def test_gradients_isolated_per_ring(self, config):
        """Gradients are isolated per classification ring."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            gradient_unclass = {"layer1": [0.1, 0.2]}
            gradient_secret = {"layer1": [0.3, 0.4]}

            # Store gradients in respective rings
            await fl.store_gradient("UNCLASS", "model-1", gradient_unclass)
            await fl.store_gradient("SECRET", "model-1", gradient_secret)

            # Verify isolation
            retrieved_unclass = await fl.get_gradient("UNCLASS", "model-1")
            retrieved_secret = await fl.get_gradient("SECRET", "model-1")

            assert retrieved_unclass != retrieved_secret
        finally:
            await fl.stop()

    @pytest.mark.asyncio
    async def test_no_cross_ring_gradient_aggregation(self, config):
        """Cross-ring gradient aggregation is blocked."""
        from src.fl import FLController

        fl = FLController(config)
        await fl.start()

        try:
            with pytest.raises(MLSViolationError):
                await fl.aggregate_gradients(
                    rings=["UNCLASS", "SECRET"],  # Cross-ring
                    model_id="model-1",
                )
        finally:
            await fl.stop()


class TestClassificationLevelEnforcement:
    """Tests for classification level enforcement."""

    @pytest.mark.asyncio
    async def test_mission_inherits_ring_classification(self, config):
        """Missions inherit classification from their ring."""
        from src.mls import MLSManager
        from src.core.mission import Mission

        mls = MLSManager(config)
        await mls.start()

        try:
            mission = Mission(
                policy_envelope={"classification_level": "SECRET"},
                scenario={},
                classification_level="SECRET",
            )

            validated = await mls.validate_mission_classification(mission)
            assert validated
            assert mission.classification_level == "SECRET"
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_action_inherits_mission_classification(self, config):
        """Actions inherit classification from their mission."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            mission_classification = "CUI"
            action = {"type": "reconnaissance", "target": "test"}

            tagged_action = await mls.tag_action(action, mission_classification)
            assert tagged_action["_classification"] == "CUI"
        finally:
            await mls.stop()


class TestCrossDomainSolution:
    """Tests for Cross-Domain Solution (CDS) requirements."""

    @pytest.mark.asyncio
    async def test_cds_required_for_secret_to_cui_transfer(self, config):
        """CDS is required for SECRET to CUI data transfer."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Without CDS, transfer should fail
            with pytest.raises(MLSViolationError):
                await mls.transfer_data(
                    source_ring="SECRET",
                    target_ring="CUI",
                    data={"test": "data"},
                    cds_approved=False,
                )
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_transfer_allowed_with_cds_approval(self, config):
        """Data transfer allowed with CDS approval."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            result = await mls.transfer_data(
                source_ring="SECRET",
                target_ring="CUI",
                data={"test": "data"},
                cds_approved=True,
            )
            assert result.approved
        finally:
            await mls.stop()


class TestAuditCompliance:
    """Tests for MLS audit compliance."""

    @pytest.mark.asyncio
    async def test_mls_operations_audited(self, config):
        """MLS operations are properly audited."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Perform operation
            await mls.validate_read("SECRET", "CUI")

            # Check audit log
            audit_log = mls.get_audit_log()
            assert len(audit_log) > 0
            assert audit_log[-1]["operation"] == "read"
            assert audit_log[-1]["source_ring"] == "SECRET"
            assert audit_log[-1]["target_ring"] == "CUI"
        finally:
            await mls.stop()

    @pytest.mark.asyncio
    async def test_mls_violations_logged(self, config):
        """MLS violations are logged to audit."""
        from src.mls import MLSManager

        mls = MLSManager(config)
        await mls.start()

        try:
            # Attempt violation
            try:
                await mls.validate_read("UNCLASS", "SECRET")
            except MLSViolationError:
                pass

            # Check audit log
            audit_log = mls.get_audit_log()
            violations = [e for e in audit_log if e.get("violation")]
            assert len(violations) > 0
        finally:
            await mls.stop()
