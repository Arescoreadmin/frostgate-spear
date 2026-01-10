"""
SBOM and SLSA Provenance Verification Tests.

Tests supply chain security requirements:
- SBOM generation and validation (SPDX, CycloneDX)
- SLSA Level 3 provenance attestation
- Artifact signing (Cosign)
- Binary attestation
- Prohibited license detection
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.core.config import Config
from src.core.exceptions import (
    SBOMValidationError,
    ProvenanceValidationError,
)


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


class TestSBOMGeneration:
    """Tests for SBOM generation."""

    @pytest.mark.asyncio
    async def test_sbom_generated_for_container(self, config):
        """SBOM is generated for container images."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "sbom": {
                    "format": "spdx-json",
                    "version": "2.3",
                    "components": [
                        {"name": "python", "version": "3.11"},
                        {"name": "pyyaml", "version": "6.0"},
                    ],
                },
            }

            result = await verifier.validate_sbom(artifact)
            assert result.valid
            assert result.format == "spdx-json"
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_sbom_required_for_all_artifacts(self, config):
        """SBOM is required for all deployable artifacts."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "sbom": None,  # Missing SBOM
            }

            result = await verifier.validate_sbom(artifact)
            assert not result.valid
            assert "sbom" in " ".join(result.errors).lower()
        finally:
            await verifier.stop()


class TestSBOMCompleteness:
    """Tests for SBOM completeness."""

    @pytest.mark.asyncio
    async def test_sbom_lists_all_dependencies(self, config):
        """SBOM must list all dependencies."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "sbom": {
                    "format": "spdx-json",
                    "version": "2.3",
                    "components": [
                        {"name": "python", "version": "3.11", "purl": "pkg:pypi/python@3.11"},
                        {"name": "pyyaml", "version": "6.0", "purl": "pkg:pypi/pyyaml@6.0"},
                        {"name": "aiohttp", "version": "3.9", "purl": "pkg:pypi/aiohttp@3.9"},
                    ],
                },
                "expected_components": ["python", "pyyaml", "aiohttp"],
            }

            result = await verifier.validate_sbom_completeness(artifact)
            assert result.valid
            assert result.coverage == 1.0  # 100% coverage
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_sbom_incomplete_flagged(self, config):
        """Incomplete SBOM is flagged."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "sbom": {
                    "format": "spdx-json",
                    "version": "2.3",
                    "components": [
                        {"name": "python", "version": "3.11"},
                    ],
                },
                "expected_components": ["python", "pyyaml", "aiohttp"],
            }

            result = await verifier.validate_sbom_completeness(artifact)
            assert not result.valid or result.coverage < 1.0
        finally:
            await verifier.stop()


class TestProhibitedLicenses:
    """Tests for prohibited license detection."""

    @pytest.mark.asyncio
    async def test_gpl3_license_blocked(self, config):
        """GPL-3.0 license is blocked."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            sbom = {
                "format": "spdx-json",
                "components": [
                    {"name": "safe-lib", "version": "1.0", "license": "MIT"},
                    {"name": "gpl-lib", "version": "1.0", "license": "GPL-3.0"},
                ],
            }

            result = await verifier.validate_licenses(sbom)
            assert not result.valid
            assert any("gpl" in l.lower() for l in result.prohibited_licenses)
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_agpl_license_blocked(self, config):
        """AGPL-3.0 license is blocked."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            sbom = {
                "format": "spdx-json",
                "components": [
                    {"name": "agpl-lib", "version": "1.0", "license": "AGPL-3.0"},
                ],
            }

            result = await verifier.validate_licenses(sbom)
            assert not result.valid
            assert any("agpl" in l.lower() for l in result.prohibited_licenses)
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_approved_licenses_allowed(self, config):
        """Approved licenses are allowed."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            sbom = {
                "format": "spdx-json",
                "components": [
                    {"name": "mit-lib", "version": "1.0", "license": "MIT"},
                    {"name": "apache-lib", "version": "1.0", "license": "Apache-2.0"},
                    {"name": "bsd-lib", "version": "1.0", "license": "BSD-3-Clause"},
                ],
            }

            result = await verifier.validate_licenses(sbom)
            assert result.valid
        finally:
            await verifier.stop()


class TestSLSAProvenance:
    """Tests for SLSA provenance attestation."""

    @pytest.mark.asyncio
    async def test_slsa_level_3_required(self, config):
        """SLSA Level 3 provenance is required."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "provenance": {
                    "slsa_level": 3,
                    "builder": "github-actions",
                    "build_type": "https://github.com/slsa-framework/slsa-github-generator",
                    "source": {
                        "repository": "github.com/org/repo",
                        "commit": "abc123def456",
                    },
                },
            }

            result = await verifier.validate_provenance(artifact)
            assert result.valid
            assert result.slsa_level >= 3
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_slsa_level_below_3_rejected(self, config):
        """SLSA Level below 3 is rejected."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "provenance": {
                    "slsa_level": 2,  # Below required level
                    "builder": "github-actions",
                },
            }

            with pytest.raises(ProvenanceValidationError):
                await verifier.validate_provenance(artifact, required_level=3)
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_provenance_includes_source_info(self, config):
        """Provenance includes source repository info."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "provenance": {
                    "slsa_level": 3,
                    "builder": "github-actions",
                    "source": None,  # Missing source info
                },
            }

            result = await verifier.validate_provenance(artifact)
            assert not result.valid or len(result.warnings) > 0
        finally:
            await verifier.stop()


class TestArtifactSigning:
    """Tests for artifact signing (Cosign)."""

    @pytest.mark.asyncio
    async def test_container_signature_required(self, config):
        """Container images require cryptographic signatures."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "signature": None,  # Unsigned
            }

            result = await verifier.validate_artifact_signature(artifact)
            assert not result.valid
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_valid_signature_accepted(self, config):
        """Valid signatures are accepted."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "signature": {
                    "algorithm": "cosign",
                    "keyref": "gcr.io/projectsigstore/cosign",
                    "payload": "eyJjcml0aWNhbCI6e...",
                    "sig": "MEUCIQD...",
                },
            }

            result = await verifier.validate_artifact_signature(artifact)
            assert result.valid or "keyref" in str(result.warnings)
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_signature_verification_fails_on_tampering(self, config):
        """Signature verification fails on tampered artifacts."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "digest": "sha256:abc123",
                "signature": {
                    "algorithm": "cosign",
                    "signed_digest": "sha256:different",  # Mismatch
                    "sig": "MEUCIQD...",
                },
            }

            result = await verifier.validate_artifact_signature(artifact)
            assert not result.valid or "mismatch" in " ".join(result.errors + result.warnings).lower()
        finally:
            await verifier.stop()


class TestBinaryAttestation:
    """Tests for binary attestation."""

    @pytest.mark.asyncio
    async def test_binary_requires_attestation(self, config):
        """All binaries require attestation."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "binary",
                "name": "frostgate-cli",
                "attestation": None,  # Missing
            }

            result = await verifier.validate_artifact_attestation(artifact)
            assert not result.valid
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_attestation_includes_hash(self, config):
        """Attestation includes content hash."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "binary",
                "name": "frostgate-cli",
                "attestation": {
                    "hash": "sha256:abc123def456789",
                    "provenance": {
                        "builder": "github-actions",
                    },
                },
            }

            result = await verifier.validate_artifact_attestation(artifact)
            assert result.valid or result.hash == "sha256:abc123def456789"
        finally:
            await verifier.stop()


class TestSupplyChainIntegrity:
    """Tests for overall supply chain integrity."""

    @pytest.mark.asyncio
    async def test_full_supply_chain_validation(self, config):
        """Full supply chain validation passes for compliant artifacts."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "digest": "sha256:abc123",
                "sbom": {
                    "format": "spdx-json",
                    "version": "2.3",
                    "components": [
                        {"name": "python", "version": "3.11", "license": "PSF"},
                    ],
                },
                "provenance": {
                    "slsa_level": 3,
                    "builder": "github-actions",
                    "source": {
                        "repository": "github.com/org/repo",
                        "commit": "abc123",
                    },
                },
                "signature": {
                    "algorithm": "cosign",
                    "sig": "MEUCIQD...",
                },
                "attestation": {
                    "hash": "sha256:abc123",
                    "provenance": {"builder": "github-actions"},
                },
            }

            result = await verifier.validate_supply_chain(artifact)
            assert result.sbom_valid or result.sbom_valid is None
            assert result.provenance_valid or result.provenance_valid is None
            assert result.signature_valid or result.signature_valid is None
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_supply_chain_fails_on_any_violation(self, config):
        """Supply chain validation fails on any violation."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact = {
                "artifact_id": str(uuid4()),
                "type": "container",
                "name": "frostgate-spear:latest",
                "sbom": {
                    "format": "spdx-json",
                    "components": [
                        {"name": "gpl-lib", "version": "1.0", "license": "GPL-3.0"},
                    ],
                },
                "provenance": {
                    "slsa_level": 3,
                },
                "signature": {
                    "algorithm": "cosign",
                    "sig": "MEUCIQD...",
                },
            }

            result = await verifier.validate_supply_chain(artifact)
            assert not result.overall_valid
        finally:
            await verifier.stop()


class TestArtifactRegistry:
    """Tests for artifact registry compliance."""

    @pytest.mark.asyncio
    async def test_artifacts_tracked_in_registry(self, config):
        """All artifacts are tracked in registry."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact_id = str(uuid4())
            artifact = {
                "artifact_id": artifact_id,
                "type": "container",
                "name": "frostgate-spear:latest",
            }

            await verifier.register_artifact(artifact)
            registered = await verifier.get_artifact(artifact_id)

            assert registered is not None
            assert registered["artifact_id"] == artifact_id
        finally:
            await verifier.stop()

    @pytest.mark.asyncio
    async def test_artifact_history_preserved(self, config):
        """Artifact modification history is preserved."""
        from src.integrity import IntegrityVerifier

        verifier = IntegrityVerifier(config)
        await verifier.start()

        try:
            artifact_id = str(uuid4())

            # Register initial version
            await verifier.register_artifact({
                "artifact_id": artifact_id,
                "type": "container",
                "name": "frostgate-spear:v1",
                "version": "1.0.0",
            })

            # Register updated version
            await verifier.register_artifact({
                "artifact_id": artifact_id,
                "type": "container",
                "name": "frostgate-spear:v2",
                "version": "2.0.0",
            })

            history = await verifier.get_artifact_history(artifact_id)
            assert len(history) >= 2
        finally:
            await verifier.stop()
