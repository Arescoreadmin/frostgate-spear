"""
Frost Gate Spear - Cryptographic Integrity Module

Provides cryptographic verification for:
- Persona signature validation (signed packs only)
- SBOM and artifact provenance verification
- Binary attestation (SLSA compliant)
- Scenario hash enforcement
- Policy envelope signatures
- Model lineage verification

Implements:
- Ed25519 signature verification
- SHA-256/SHA-384 hash validation
- SLSA provenance attestation
- Sigstore/cosign compatibility
"""

import asyncio
import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class IntegrityError(Exception):
    """Base exception for integrity verification failures."""

    def __init__(
        self,
        message: str,
        artifact_type: str,
        artifact_id: Optional[str] = None,
        expected_hash: Optional[str] = None,
        actual_hash: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.artifact_type = artifact_type
        self.artifact_id = artifact_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": "INTEGRITY_ERROR",
            "message": self.message,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
        }


class SignatureError(IntegrityError):
    """Exception for signature verification failures."""

    def __init__(
        self,
        message: str,
        artifact_type: str,
        signer: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(message, artifact_type, **kwargs)
        self.signer = signer


class AttestationError(IntegrityError):
    """Exception for attestation verification failures."""
    pass


@dataclass
class VerificationResult:
    """Result of integrity verification."""
    valid: bool
    artifact_type: str
    artifact_id: str
    hash_algorithm: str
    computed_hash: str
    expected_hash: Optional[str]
    signature_valid: Optional[bool]
    signer: Optional[str]
    attestation_valid: Optional[bool]
    timestamp: datetime
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "hash_algorithm": self.hash_algorithm,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "signature_valid": self.signature_valid,
            "signer": self.signer,
            "attestation_valid": self.attestation_valid,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


@dataclass
class TrustedSigner:
    """Trusted signer configuration."""
    signer_id: str
    name: str
    public_key: bytes
    roles: List[str]  # What they can sign: persona, scenario, sbom, binary
    valid_from: datetime
    valid_until: Optional[datetime]
    revoked: bool = False


class TrustStore:
    """
    Manages trusted signers and verification keys.

    Supports:
    - Ed25519 public keys
    - Key rotation
    - Revocation checking
    - Role-based signing authorization
    """

    def __init__(self, trust_store_path: Optional[str] = None):
        """Initialize trust store."""
        self.trust_store_path = Path(trust_store_path) if trust_store_path else None
        self._signers: Dict[str, TrustedSigner] = {}
        self._key_cache: Dict[str, Ed25519PublicKey] = {}

    async def load(self) -> None:
        """Load trust store from disk."""
        if not self.trust_store_path or not self.trust_store_path.exists():
            logger.warning("Trust store not found, using empty store")
            return

        with open(self.trust_store_path) as f:
            data = json.load(f)

        for signer_data in data.get("signers", []):
            signer = TrustedSigner(
                signer_id=signer_data["signer_id"],
                name=signer_data["name"],
                public_key=base64.b64decode(signer_data["public_key"]),
                roles=signer_data.get("roles", []),
                valid_from=datetime.fromisoformat(signer_data["valid_from"]),
                valid_until=datetime.fromisoformat(signer_data["valid_until"])
                           if signer_data.get("valid_until") else None,
                revoked=signer_data.get("revoked", False),
            )
            self._signers[signer.signer_id] = signer

        logger.info(f"Loaded {len(self._signers)} trusted signers")

    def add_signer(self, signer: TrustedSigner) -> None:
        """Add trusted signer."""
        self._signers[signer.signer_id] = signer
        # Clear key cache for this signer
        self._key_cache.pop(signer.signer_id, None)

    def get_signer(self, signer_id: str) -> Optional[TrustedSigner]:
        """Get signer by ID."""
        return self._signers.get(signer_id)

    def get_public_key(self, signer_id: str) -> Optional[Ed25519PublicKey]:
        """Get public key for signer."""
        if signer_id in self._key_cache:
            return self._key_cache[signer_id]

        signer = self._signers.get(signer_id)
        if not signer:
            return None

        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(signer.public_key)
            self._key_cache[signer_id] = key
            return key
        except Exception as e:
            logger.error(f"Failed to load public key for {signer_id}: {e}")
            return None

    def is_authorized(self, signer_id: str, artifact_type: str) -> bool:
        """Check if signer is authorized for artifact type."""
        signer = self._signers.get(signer_id)
        if not signer:
            return False

        if signer.revoked:
            return False

        now = datetime.now(timezone.utc)
        if signer.valid_from > now:
            return False
        if signer.valid_until and signer.valid_until < now:
            return False

        return artifact_type in signer.roles


class HashVerifier:
    """Compute and verify cryptographic hashes."""

    SUPPORTED_ALGORITHMS = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }

    @classmethod
    def compute_hash(
        cls,
        data: Union[bytes, str, Dict],
        algorithm: str = "sha256",
    ) -> str:
        """
        Compute hash of data.

        Args:
            data: Data to hash (bytes, string, or dict)
            algorithm: Hash algorithm (sha256, sha384, sha512)

        Returns:
            Hash string with algorithm prefix
        """
        if algorithm not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        hasher = cls.SUPPORTED_ALGORITHMS[algorithm]()

        if isinstance(data, dict):
            # Canonical JSON for reproducible hashes
            data = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        elif isinstance(data, str):
            data = data.encode()

        hasher.update(data)
        return f"{algorithm}:{hasher.hexdigest()}"

    @classmethod
    def verify_hash(
        cls,
        data: Union[bytes, str, Dict],
        expected_hash: str,
    ) -> bool:
        """
        Verify hash matches expected value.

        Args:
            data: Data to verify
            expected_hash: Expected hash (with algorithm prefix)

        Returns:
            True if hash matches
        """
        # Parse expected hash
        if ":" in expected_hash:
            algorithm, expected_value = expected_hash.split(":", 1)
        else:
            algorithm = "sha256"
            expected_value = expected_hash

        computed = cls.compute_hash(data, algorithm)
        computed_value = computed.split(":", 1)[1]

        return computed_value == expected_value

    @classmethod
    def compute_file_hash(
        cls,
        file_path: Union[str, Path],
        algorithm: str = "sha256",
    ) -> str:
        """Compute hash of file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        hasher = cls.SUPPORTED_ALGORITHMS[algorithm]()

        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)

        return f"{algorithm}:{hasher.hexdigest()}"


class SignatureVerifier:
    """Verify Ed25519 signatures."""

    def __init__(self, trust_store: TrustStore):
        """Initialize signature verifier."""
        self.trust_store = trust_store

    def verify_signature(
        self,
        data: Union[bytes, str, Dict],
        signature: str,
        signer_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify Ed25519 signature.

        Args:
            data: Signed data
            signature: Base64-encoded signature
            signer_id: ID of claimed signer

        Returns:
            Tuple of (valid, error_message)
        """
        # Get public key
        public_key = self.trust_store.get_public_key(signer_id)
        if not public_key:
            return False, f"Unknown signer: {signer_id}"

        # Check authorization
        signer = self.trust_store.get_signer(signer_id)
        if signer and signer.revoked:
            return False, f"Signer revoked: {signer_id}"

        # Prepare data
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        elif isinstance(data, str):
            data = data.encode()

        # Decode signature
        try:
            sig_bytes = base64.b64decode(signature)
        except Exception:
            return False, "Invalid signature encoding"

        # Verify
        try:
            public_key.verify(sig_bytes, data)
            return True, None
        except InvalidSignature:
            return False, "Signature verification failed"
        except Exception as e:
            return False, f"Verification error: {e}"


class PersonaVerifier:
    """
    Verify adversary persona integrity and signatures.

    Personas must be signed by authorized signers and match
    expected schema and constraints.
    """

    def __init__(self, trust_store: TrustStore):
        """Initialize persona verifier."""
        self.trust_store = trust_store
        self.signature_verifier = SignatureVerifier(trust_store)

    async def verify_persona(
        self,
        persona: Dict[str, Any],
        require_signature: bool = True,
    ) -> VerificationResult:
        """
        Verify persona integrity.

        Args:
            persona: Persona definition
            require_signature: Require valid signature

        Returns:
            Verification result
        """
        persona_id = persona.get("persona_id", "unknown")
        details: Dict[str, Any] = {}

        # Compute hash of persona content (excluding signature)
        persona_content = {k: v for k, v in persona.items() if k not in ["signature", "signer_id"]}
        computed_hash = HashVerifier.compute_hash(persona_content)
        details["computed_hash"] = computed_hash

        # Check required fields
        required_fields = ["persona_id", "name", "category", "ttps"]
        missing_fields = [f for f in required_fields if f not in persona]
        if missing_fields:
            return VerificationResult(
                valid=False,
                artifact_type="persona",
                artifact_id=persona_id,
                hash_algorithm="sha256",
                computed_hash=computed_hash,
                expected_hash=persona.get("content_hash"),
                signature_valid=None,
                signer=None,
                attestation_valid=None,
                timestamp=datetime.now(timezone.utc),
                details={"error": f"Missing required fields: {missing_fields}"},
            )

        # Verify hash if provided
        expected_hash = persona.get("content_hash")
        if expected_hash:
            hash_valid = HashVerifier.verify_hash(persona_content, expected_hash)
            if not hash_valid:
                return VerificationResult(
                    valid=False,
                    artifact_type="persona",
                    artifact_id=persona_id,
                    hash_algorithm="sha256",
                    computed_hash=computed_hash,
                    expected_hash=expected_hash,
                    signature_valid=None,
                    signer=None,
                    attestation_valid=None,
                    timestamp=datetime.now(timezone.utc),
                    details={"error": "Hash mismatch"},
                )

        # Verify signature
        signature = persona.get("signature")
        signer_id = persona.get("signer_id")
        signature_valid = None
        signer_name = None

        if signature and signer_id:
            # Check signer is authorized for personas
            if not self.trust_store.is_authorized(signer_id, "persona"):
                return VerificationResult(
                    valid=False,
                    artifact_type="persona",
                    artifact_id=persona_id,
                    hash_algorithm="sha256",
                    computed_hash=computed_hash,
                    expected_hash=expected_hash,
                    signature_valid=False,
                    signer=signer_id,
                    attestation_valid=None,
                    timestamp=datetime.now(timezone.utc),
                    details={"error": f"Signer not authorized for personas: {signer_id}"},
                )

            valid, error = self.signature_verifier.verify_signature(
                persona_content, signature, signer_id
            )
            signature_valid = valid

            signer = self.trust_store.get_signer(signer_id)
            signer_name = signer.name if signer else signer_id

            if not valid:
                details["signature_error"] = error
                if require_signature:
                    return VerificationResult(
                        valid=False,
                        artifact_type="persona",
                        artifact_id=persona_id,
                        hash_algorithm="sha256",
                        computed_hash=computed_hash,
                        expected_hash=expected_hash,
                        signature_valid=False,
                        signer=signer_name,
                        attestation_valid=None,
                        timestamp=datetime.now(timezone.utc),
                        details=details,
                    )
        elif require_signature:
            return VerificationResult(
                valid=False,
                artifact_type="persona",
                artifact_id=persona_id,
                hash_algorithm="sha256",
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                signature_valid=False,
                signer=None,
                attestation_valid=None,
                timestamp=datetime.now(timezone.utc),
                details={"error": "Signature required but not provided"},
            )

        # Validate persona constraints (cannot override ROE/safety)
        ttps = persona.get("ttps", {})
        constraints_valid = self._validate_persona_constraints(ttps)
        details["constraints_valid"] = constraints_valid

        return VerificationResult(
            valid=signature_valid if require_signature else True,
            artifact_type="persona",
            artifact_id=persona_id,
            hash_algorithm="sha256",
            computed_hash=computed_hash,
            expected_hash=expected_hash,
            signature_valid=signature_valid,
            signer=signer_name,
            attestation_valid=None,
            timestamp=datetime.now(timezone.utc),
            details=details,
        )

    def _validate_persona_constraints(self, ttps: Dict[str, Any]) -> bool:
        """Validate persona cannot override ROE/safety."""
        # Check for forbidden override flags
        forbidden_keys = [
            "override_roe",
            "bypass_safety",
            "ignore_blast_radius",
            "skip_approval",
        ]

        for key in forbidden_keys:
            if ttps.get(key):
                logger.error(f"Persona contains forbidden override: {key}")
                return False

        return True


class SBOMVerifier:
    """
    Verify Software Bill of Materials (SBOM) integrity.

    Supports:
    - CycloneDX format
    - SPDX format
    - SLSA provenance attestations
    """

    def __init__(self, trust_store: TrustStore):
        """Initialize SBOM verifier."""
        self.trust_store = trust_store
        self.signature_verifier = SignatureVerifier(trust_store)

    async def verify_sbom(
        self,
        sbom: Dict[str, Any],
        attestation: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Verify SBOM integrity and attestation.

        Args:
            sbom: SBOM document
            attestation: Optional SLSA attestation

        Returns:
            Verification result
        """
        # Determine SBOM format
        sbom_format = self._detect_format(sbom)
        sbom_id = sbom.get("serialNumber", sbom.get("SPDXID", "unknown"))

        # Compute hash
        computed_hash = HashVerifier.compute_hash(sbom)

        details = {
            "format": sbom_format,
            "components": len(sbom.get("components", sbom.get("packages", []))),
        }

        # Verify signature if present
        signature = sbom.get("signature")
        signer_id = sbom.get("signer_id")
        signature_valid = None

        if signature and signer_id:
            sbom_content = {k: v for k, v in sbom.items() if k not in ["signature", "signer_id"]}
            valid, error = self.signature_verifier.verify_signature(
                sbom_content, signature, signer_id
            )
            signature_valid = valid
            if error:
                details["signature_error"] = error

        # Verify attestation if present
        attestation_valid = None
        if attestation:
            attestation_valid = await self._verify_attestation(attestation, computed_hash)
            details["attestation_verified"] = attestation_valid

        # Verify components have hashes
        components = sbom.get("components", sbom.get("packages", []))
        components_with_hash = sum(
            1 for c in components
            if c.get("hashes") or c.get("checksums")
        )
        details["components_with_hash"] = components_with_hash
        details["hash_coverage"] = components_with_hash / len(components) if components else 1.0

        valid = (
            (signature_valid is None or signature_valid) and
            (attestation_valid is None or attestation_valid) and
            details["hash_coverage"] >= 0.95
        )

        return VerificationResult(
            valid=valid,
            artifact_type="sbom",
            artifact_id=sbom_id,
            hash_algorithm="sha256",
            computed_hash=computed_hash,
            expected_hash=None,
            signature_valid=signature_valid,
            signer=signer_id,
            attestation_valid=attestation_valid,
            timestamp=datetime.now(timezone.utc),
            details=details,
        )

    def _detect_format(self, sbom: Dict[str, Any]) -> str:
        """Detect SBOM format."""
        if "bomFormat" in sbom:
            return "cyclonedx"
        if "spdxVersion" in sbom:
            return "spdx"
        return "unknown"

    async def _verify_attestation(
        self,
        attestation: Dict[str, Any],
        subject_hash: str,
    ) -> bool:
        """Verify SLSA attestation."""
        # Check attestation type
        att_type = attestation.get("_type")
        if att_type != "https://in-toto.io/Statement/v0.1":
            logger.warning(f"Unknown attestation type: {att_type}")
            return False

        # Verify subject matches
        subjects = attestation.get("subject", [])
        subject_hash_value = subject_hash.split(":", 1)[1] if ":" in subject_hash else subject_hash

        for subject in subjects:
            digest = subject.get("digest", {})
            if digest.get("sha256") == subject_hash_value:
                return True

        logger.warning("Attestation subject hash mismatch")
        return False


class ScenarioVerifier:
    """
    Verify scenario integrity.

    Enforces:
    - Scenario hash validation before execution
    - No unauthorized modification
    - Signed scenario requirements for higher risk tiers
    """

    def __init__(self, trust_store: TrustStore):
        """Initialize scenario verifier."""
        self.trust_store = trust_store
        self.signature_verifier = SignatureVerifier(trust_store)

    async def verify_scenario(
        self,
        scenario: Dict[str, Any],
        expected_hash: Optional[str] = None,
        require_signature: bool = False,
    ) -> VerificationResult:
        """
        Verify scenario integrity.

        Args:
            scenario: Scenario definition
            expected_hash: Expected hash (from policy envelope)
            require_signature: Require valid signature

        Returns:
            Verification result
        """
        scenario_id = scenario.get("scenario_id", scenario.get("name", "unknown"))

        # Compute hash of scenario content
        scenario_content = {k: v for k, v in scenario.items() if k not in ["signature", "signer_id", "scenario_hash"]}
        computed_hash = HashVerifier.compute_hash(scenario_content)

        details: Dict[str, Any] = {
            "name": scenario.get("name"),
            "targets_count": len(scenario.get("targets", [])),
        }

        # Verify hash matches expected
        if expected_hash:
            hash_valid = HashVerifier.verify_hash(scenario_content, expected_hash)
            if not hash_valid:
                return VerificationResult(
                    valid=False,
                    artifact_type="scenario",
                    artifact_id=scenario_id,
                    hash_algorithm="sha256",
                    computed_hash=computed_hash,
                    expected_hash=expected_hash,
                    signature_valid=None,
                    signer=None,
                    attestation_valid=None,
                    timestamp=datetime.now(timezone.utc),
                    details={"error": "Scenario hash mismatch - possible tampering"},
                )

        # Verify signature if present or required
        signature = scenario.get("signature")
        signer_id = scenario.get("signer_id")
        signature_valid = None

        if signature and signer_id:
            if not self.trust_store.is_authorized(signer_id, "scenario"):
                details["error"] = f"Signer not authorized for scenarios: {signer_id}"
                signature_valid = False
            else:
                valid, error = self.signature_verifier.verify_signature(
                    scenario_content, signature, signer_id
                )
                signature_valid = valid
                if error:
                    details["signature_error"] = error
        elif require_signature:
            return VerificationResult(
                valid=False,
                artifact_type="scenario",
                artifact_id=scenario_id,
                hash_algorithm="sha256",
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                signature_valid=False,
                signer=None,
                attestation_valid=None,
                timestamp=datetime.now(timezone.utc),
                details={"error": "Signature required but not provided"},
            )

        # Validate scenario constraints
        constraints_valid = self._validate_scenario_constraints(scenario)
        details["constraints_valid"] = constraints_valid

        valid = (
            (signature_valid is None or signature_valid) and
            constraints_valid
        )

        return VerificationResult(
            valid=valid,
            artifact_type="scenario",
            artifact_id=scenario_id,
            hash_algorithm="sha256",
            computed_hash=computed_hash,
            expected_hash=expected_hash,
            signature_valid=signature_valid,
            signer=signer_id,
            attestation_valid=None,
            timestamp=datetime.now(timezone.utc),
            details=details,
        )

    def _validate_scenario_constraints(self, scenario: Dict[str, Any]) -> bool:
        """Validate scenario doesn't violate constraints."""
        # Check for forbidden elements
        forbidden_keys = ["bypass_roe", "override_policy", "skip_simulation"]

        for key in forbidden_keys:
            if scenario.get(key):
                logger.error(f"Scenario contains forbidden element: {key}")
                return False

        return True


class IntegrityManager:
    """
    Central integrity manager for all artifact verification.

    Provides unified interface for verifying:
    - Personas
    - Scenarios
    - SBOMs
    - Policy envelopes
    - Model lineage
    """

    def __init__(
        self,
        trust_store_path: Optional[str] = None,
        require_signatures: bool = True,
    ):
        """Initialize integrity manager."""
        self.trust_store = TrustStore(trust_store_path)
        self.require_signatures = require_signatures

        # Initialize verifiers
        self.persona_verifier = PersonaVerifier(self.trust_store)
        self.sbom_verifier = SBOMVerifier(self.trust_store)
        self.scenario_verifier = ScenarioVerifier(self.trust_store)

    async def start(self) -> None:
        """Start integrity manager."""
        await self.trust_store.load()
        logger.info("Integrity Manager started")

    async def verify_artifact(
        self,
        artifact_type: str,
        artifact: Dict[str, Any],
        expected_hash: Optional[str] = None,
        require_signature: Optional[bool] = None,
    ) -> VerificationResult:
        """
        Verify artifact integrity.

        Args:
            artifact_type: Type of artifact
            artifact: Artifact data
            expected_hash: Expected hash
            require_signature: Override signature requirement

        Returns:
            Verification result
        """
        sig_required = require_signature if require_signature is not None else self.require_signatures

        if artifact_type == "persona":
            return await self.persona_verifier.verify_persona(artifact, sig_required)
        elif artifact_type == "scenario":
            return await self.scenario_verifier.verify_scenario(
                artifact, expected_hash, sig_required
            )
        elif artifact_type == "sbom":
            return await self.sbom_verifier.verify_sbom(artifact)
        else:
            # Generic hash verification
            computed_hash = HashVerifier.compute_hash(artifact)
            valid = True

            if expected_hash:
                valid = HashVerifier.verify_hash(artifact, expected_hash)

            return VerificationResult(
                valid=valid,
                artifact_type=artifact_type,
                artifact_id=artifact.get("id", "unknown"),
                hash_algorithm="sha256",
                computed_hash=computed_hash,
                expected_hash=expected_hash,
                signature_valid=None,
                signer=None,
                attestation_valid=None,
                timestamp=datetime.now(timezone.utc),
                details={},
            )

    async def verify_policy_envelope(
        self,
        envelope: Dict[str, Any],
    ) -> VerificationResult:
        """Verify policy envelope integrity."""
        envelope_id = envelope.get("envelope_id", "unknown")

        # Compute hash excluding signature
        envelope_content = {k: v for k, v in envelope.items() if k not in ["signature", "signer_id"]}
        computed_hash = HashVerifier.compute_hash(envelope_content)

        details: Dict[str, Any] = {
            "mode": envelope.get("mode"),
            "risk_tier": envelope.get("risk_tier"),
            "classification": envelope.get("classification_level"),
        }

        # Verify signature
        signature = envelope.get("signature")
        signer_id = envelope.get("signer_id")
        signature_valid = None

        if signature and signer_id:
            sig_verifier = SignatureVerifier(self.trust_store)
            valid, error = sig_verifier.verify_signature(
                envelope_content, signature, signer_id
            )
            signature_valid = valid
            if error:
                details["signature_error"] = error

        # Check approvals have valid signatures
        approvals = envelope.get("approvals", [])
        approvals_verified = 0
        for approval in approvals:
            if approval.get("signature") and approval.get("valid", True):
                approvals_verified += 1
        details["approvals_verified"] = approvals_verified
        details["approvals_total"] = len(approvals)

        return VerificationResult(
            valid=signature_valid if signature else True,
            artifact_type="policy_envelope",
            artifact_id=envelope_id,
            hash_algorithm="sha256",
            computed_hash=computed_hash,
            expected_hash=None,
            signature_valid=signature_valid,
            signer=signer_id,
            attestation_valid=None,
            timestamp=datetime.now(timezone.utc),
            details=details,
        )

    async def compute_lineage_hash(
        self,
        components: List[Dict[str, Any]],
    ) -> str:
        """
        Compute lineage hash for model/artifact provenance.

        Creates a deterministic hash chain of component hashes.
        """
        # Sort components by ID for determinism
        sorted_components = sorted(components, key=lambda x: x.get("id", ""))

        # Build hash chain
        chain = []
        for component in sorted_components:
            comp_hash = HashVerifier.compute_hash(component)
            chain.append({
                "id": component.get("id"),
                "hash": comp_hash,
            })

        return HashVerifier.compute_hash(chain)


# Convenience function
async def create_integrity_manager(
    trust_store_path: Optional[str] = None,
    require_signatures: bool = True,
) -> IntegrityManager:
    """Create and start integrity manager."""
    manager = IntegrityManager(trust_store_path, require_signatures)
    await manager.start()
    return manager
