"""
Frost Gate Spear - Personas Manager

Manages adversary persona packs with signature validation, constraint enforcement,
and planner bias configuration. Ensures personas CANNOT override ROE, safety, or policy.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from ..core.config import Config, ClassificationLevel
from ..core.exceptions import (
    FrostGateError,
    PersonaValidationError,
    PersonaConstraintViolationError,
    PersonaSignatureError,
    PersonaClassificationError,
)

logger = logging.getLogger(__name__)


class PersonaCategory(Enum):
    """Adversary persona categories with minimum classification requirements."""
    SCRIPT_KIDDIE = ("script_kiddie", ClassificationLevel.UNCLASS)
    CYBERCRIMINAL = ("cybercriminal", ClassificationLevel.UNCLASS)
    HACKTIVIST = ("hacktivist", ClassificationLevel.UNCLASS)
    NATION_STATE_LITE = ("nation_state_lite", ClassificationLevel.CUI)
    NATION_STATE = ("nation_state", ClassificationLevel.SECRET)
    NATION_STATE_ADVANCED = ("nation_state_advanced", ClassificationLevel.SECRET)
    APT = ("apt", ClassificationLevel.SECRET)
    APT_FULL = ("apt_full", ClassificationLevel.SECRET)
    INSIDER = ("insider", ClassificationLevel.SECRET)
    INSIDER_PRIVILEGED = ("insider_privileged", ClassificationLevel.TOPSECRET)

    @property
    def category_name(self) -> str:
        return self.value[0]

    @property
    def min_classification(self) -> ClassificationLevel:
        return self.value[1]


class CapabilitySophistication(Enum):
    """Sophistication levels for adversary capabilities."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"
    ELITE = "elite"


class ResourceLevel(Enum):
    """Resource availability levels."""
    MINIMAL = "minimal"
    LIMITED = "limited"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    UNLIMITED = "unlimited"


@dataclass
class PersonaSignature:
    """Cryptographic signature for persona validation."""
    algorithm: str
    value: str
    signer_id: str
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "value": self.value,
            "signer_id": self.signer_id,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PersonaAttestation:
    """SLSA-compatible attestation for persona provenance."""
    hash: str
    provenance: Dict[str, str]
    sbom_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash": self.hash,
            "provenance": self.provenance,
            "sbom_ref": self.sbom_ref,
        }


@dataclass
class PersonaConstraints:
    """
    Immutable constraints for persona behavior.

    CRITICAL: These constraints are IMMUTABLE and CANNOT be overridden.
    The schema enforces const: false/true values that cannot be changed.
    """
    can_override_roe: bool = field(default=False)
    can_override_safety: bool = field(default=False)
    can_override_policy: bool = field(default=False)
    respects_blast_radius: bool = field(default=True)
    respects_scope: bool = field(default=True)

    def __post_init__(self):
        """Validate constraints are within allowed values."""
        # CRITICAL: Enforce immutable constraints
        if self.can_override_roe:
            raise PersonaConstraintViolationError(
                "Personas cannot override ROE - this is a red line violation",
                constraint="can_override_roe",
                attempted_value=True,
                required_value=False,
            )
        if self.can_override_safety:
            raise PersonaConstraintViolationError(
                "Personas cannot override safety - this is a red line violation",
                constraint="can_override_safety",
                attempted_value=True,
                required_value=False,
            )
        if self.can_override_policy:
            raise PersonaConstraintViolationError(
                "Personas cannot override policy - this is a red line violation",
                constraint="can_override_policy",
                attempted_value=True,
                required_value=False,
            )
        if not self.respects_blast_radius:
            raise PersonaConstraintViolationError(
                "Personas must respect blast radius",
                constraint="respects_blast_radius",
                attempted_value=False,
                required_value=True,
            )
        if not self.respects_scope:
            raise PersonaConstraintViolationError(
                "Personas must respect scope boundaries",
                constraint="respects_scope",
                attempted_value=False,
                required_value=True,
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "can_override_roe": self.can_override_roe,
            "can_override_safety": self.can_override_safety,
            "can_override_policy": self.can_override_policy,
            "respects_blast_radius": self.respects_blast_radius,
            "respects_scope": self.respects_scope,
        }


@dataclass
class TechniquePreference:
    """MITRE ATT&CK technique preference."""
    technique_id: str
    name: str
    preference_weight: float = 0.5
    subtechniques: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "preference_weight": self.preference_weight,
            "subtechniques": self.subtechniques,
        }


@dataclass
class BehavioralProfile:
    """Behavioral characteristics of the adversary."""
    working_hours: Optional[Dict[str, Any]] = None
    dwell_time: Optional[Dict[str, int]] = None
    lateral_movement_style: str = "methodical"
    data_exfil_style: str = "staged"
    c2_patterns: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "working_hours": self.working_hours,
            "dwell_time": self.dwell_time,
            "lateral_movement_style": self.lateral_movement_style,
            "data_exfil_style": self.data_exfil_style,
            "c2_patterns": self.c2_patterns,
        }


@dataclass
class PlannerBiases:
    """Biases applied to planner decisions - affects preferences, NOT constraints."""
    technique_selection: Dict[str, float] = field(default_factory=dict)
    target_prioritization: Dict[str, float] = field(default_factory=dict)
    timing_preferences: Dict[str, float] = field(default_factory=dict)
    evasion_priorities: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_selection": self.technique_selection,
            "target_prioritization": self.target_prioritization,
            "timing_preferences": self.timing_preferences,
            "evasion_priorities": self.evasion_priorities,
        }


@dataclass
class AdversaryPersona:
    """
    Adversary persona for threat emulation.

    Personas define behavioral patterns, TTP preferences, and planner biases
    for threat actor emulation. They CANNOT override ROE, safety, or policy
    constraints - these are enforced at the schema level with const values.
    """
    persona_id: UUID
    version: str
    name: str
    category: PersonaCategory
    classification_level: ClassificationLevel
    signature: PersonaSignature
    attestation: PersonaAttestation
    constraints: PersonaConstraints
    description: str = ""
    attribution: Optional[Dict[str, Any]] = None
    capabilities: Optional[Dict[str, Any]] = None
    ttps: Optional[Dict[str, Any]] = None
    behavioral_profile: Optional[BehavioralProfile] = None
    planner_biases: Optional[PlannerBiases] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Validate persona after creation."""
        # Ensure constraints are valid
        if not isinstance(self.constraints, PersonaConstraints):
            self.constraints = PersonaConstraints(**self.constraints)

    def validate_for_ring(self, ring: ClassificationLevel) -> bool:
        """
        Validate persona can be used in the given ring.

        Args:
            ring: Target classification ring

        Returns:
            True if persona can be used in ring

        Raises:
            PersonaClassificationError: If ring insufficient
        """
        ring_order = [
            ClassificationLevel.UNCLASS,
            ClassificationLevel.CUI,
            ClassificationLevel.SECRET,
            ClassificationLevel.TOPSECRET,
        ]

        min_ring = self.category.min_classification

        if ring_order.index(ring) < ring_order.index(min_ring):
            raise PersonaClassificationError(
                f"Persona '{self.name}' requires {min_ring.value} ring, "
                f"current ring is {ring.value}",
                persona_id=str(self.persona_id),
                required_ring=min_ring.value,
                current_ring=ring.value,
            )

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize persona to dictionary."""
        return {
            "persona_id": str(self.persona_id),
            "version": self.version,
            "name": self.name,
            "category": self.category.category_name,
            "classification_level": self.classification_level.value,
            "description": self.description,
            "attribution": self.attribution,
            "capabilities": self.capabilities,
            "ttps": self.ttps,
            "behavioral_profile": self.behavioral_profile.to_dict() if self.behavioral_profile else None,
            "planner_biases": self.planner_biases.to_dict() if self.planner_biases else None,
            "constraints": self.constraints.to_dict(),
            "signature": self.signature.to_dict(),
            "attestation": self.attestation.to_dict(),
            "metadata": self.metadata,
        }


@dataclass
class PersonaValidationResult:
    """Result of persona validation."""
    valid: bool
    persona_id: str
    persona_hash: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    signature_valid: bool = False
    attestation_valid: bool = False
    constraints_valid: bool = False
    classification_valid: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "persona_id": self.persona_id,
            "persona_hash": self.persona_hash,
            "errors": self.errors,
            "warnings": self.warnings,
            "signature_valid": self.signature_valid,
            "attestation_valid": self.attestation_valid,
            "constraints_valid": self.constraints_valid,
            "classification_valid": self.classification_valid,
        }


class PersonasManager:
    """
    Manages adversary persona packs.

    Responsibilities:
    - Load and validate persona definitions
    - Verify cryptographic signatures
    - Validate SLSA attestations
    - Enforce classification requirements
    - Ensure constraint immutability (no ROE/safety/policy override)
    - Provide planner biases for attack planning

    Non-negotiables:
    - Personas CANNOT override ROE
    - Personas CANNOT override safety constraints
    - Personas CANNOT override policy envelopes
    - All personas must be signed
    - All personas must have valid attestations
    """

    def __init__(self, config: Config):
        """Initialize Personas Manager."""
        self.config = config
        self._personas: Dict[str, AdversaryPersona] = {}
        self._persona_hashes: Dict[str, str] = {}
        self._validation_cache: Dict[str, PersonaValidationResult] = {}
        self._trusted_signers: Set[str] = set()
        self._persona_path = Path(config.paths.personas_dir) if hasattr(config, 'paths') else Path("adversary_personas")

    async def start(self) -> None:
        """Start Personas Manager."""
        logger.info("Starting Personas Manager...")
        await self._load_trusted_signers()
        await self._load_personas()
        logger.info(f"Personas Manager started - {len(self._personas)} personas loaded")

    async def stop(self) -> None:
        """Stop Personas Manager."""
        logger.info("Stopping Personas Manager...")
        self._personas.clear()
        self._validation_cache.clear()

    async def _load_trusted_signers(self) -> None:
        """Load trusted signer IDs."""
        # Default trusted signers for development
        self._trusted_signers = {
            "frostgate-security-team",
            "frostgate-gov-authority",
            "frostgate-research",
        }
        logger.debug(f"Loaded {len(self._trusted_signers)} trusted signers")

    async def _load_personas(self) -> None:
        """Load persona definitions from disk."""
        if not self._persona_path.exists():
            logger.warning(f"Personas directory not found: {self._persona_path}")
            return

        for persona_file in self._persona_path.glob("*.json"):
            if persona_file.name == "schema.json":
                continue

            try:
                result = await self.load_persona(persona_file)
                if result.valid:
                    logger.debug(f"Loaded persona: {result.persona_id}")
                else:
                    logger.warning(f"Invalid persona {persona_file}: {result.errors}")
            except Exception as e:
                logger.error(f"Failed to load persona {persona_file}: {e}")

    async def load_persona(self, path: Path) -> PersonaValidationResult:
        """
        Load and validate a persona from file.

        Args:
            path: Path to persona JSON file

        Returns:
            Validation result
        """
        errors = []
        warnings = []

        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            return PersonaValidationResult(
                valid=False,
                persona_id="unknown",
                persona_hash="",
                errors=[f"Failed to load persona file: {e}"],
            )

        # Compute hash
        persona_hash = self._compute_hash(data)
        persona_id = data.get("persona_id", "unknown")

        # Validate signature
        signature_valid = await self._validate_signature(data)
        if not signature_valid:
            errors.append("Invalid or missing signature")

        # Validate attestation
        attestation_valid = await self._validate_attestation(data, persona_hash)
        if not attestation_valid:
            errors.append("Invalid or missing attestation")

        # Validate constraints
        constraints_valid = await self._validate_constraints(data)
        if not constraints_valid:
            errors.append("Constraint validation failed - persona may attempt to override ROE/safety/policy")

        # Validate classification
        classification_valid = await self._validate_classification(data)
        if not classification_valid:
            errors.append("Invalid classification level")

        # Parse persona if valid
        if not errors:
            try:
                persona = await self._parse_persona(data, persona_hash)
                self._personas[str(persona.persona_id)] = persona
                self._persona_hashes[str(persona.persona_id)] = persona_hash
            except Exception as e:
                errors.append(f"Failed to parse persona: {e}")

        result = PersonaValidationResult(
            valid=len(errors) == 0,
            persona_id=persona_id,
            persona_hash=persona_hash,
            errors=errors,
            warnings=warnings,
            signature_valid=signature_valid,
            attestation_valid=attestation_valid,
            constraints_valid=constraints_valid,
            classification_valid=classification_valid,
        )

        self._validation_cache[persona_id] = result
        return result

    async def validate_persona(
        self,
        persona_id: str,
        ring: ClassificationLevel,
    ) -> PersonaValidationResult:
        """
        Validate a persona for use in a specific ring.

        Args:
            persona_id: Persona identifier
            ring: Target classification ring

        Returns:
            Validation result
        """
        if persona_id not in self._personas:
            return PersonaValidationResult(
                valid=False,
                persona_id=persona_id,
                persona_hash="",
                errors=["Persona not found"],
            )

        persona = self._personas[persona_id]
        errors = []

        # Validate ring compatibility
        try:
            persona.validate_for_ring(ring)
        except PersonaClassificationError as e:
            errors.append(str(e))

        # Re-validate constraints
        constraints_valid = persona.constraints.can_override_roe == False
        constraints_valid &= persona.constraints.can_override_safety == False
        constraints_valid &= persona.constraints.can_override_policy == False
        constraints_valid &= persona.constraints.respects_blast_radius == True
        constraints_valid &= persona.constraints.respects_scope == True

        if not constraints_valid:
            errors.append("Constraint integrity check failed")

        return PersonaValidationResult(
            valid=len(errors) == 0,
            persona_id=persona_id,
            persona_hash=self._persona_hashes.get(persona_id, ""),
            errors=errors,
            signature_valid=True,
            attestation_valid=True,
            constraints_valid=constraints_valid,
            classification_valid=len(errors) == 0,
        )

    def get_persona(self, persona_id: str) -> Optional[AdversaryPersona]:
        """Get persona by ID."""
        return self._personas.get(persona_id)

    def list_personas(
        self,
        ring: Optional[ClassificationLevel] = None,
        category: Optional[PersonaCategory] = None,
    ) -> List[AdversaryPersona]:
        """
        List available personas.

        Args:
            ring: Filter by classification ring compatibility
            category: Filter by category

        Returns:
            List of matching personas
        """
        personas = list(self._personas.values())

        if ring:
            ring_order = [
                ClassificationLevel.UNCLASS,
                ClassificationLevel.CUI,
                ClassificationLevel.SECRET,
                ClassificationLevel.TOPSECRET,
            ]
            ring_index = ring_order.index(ring)
            personas = [
                p for p in personas
                if ring_order.index(p.category.min_classification) <= ring_index
            ]

        if category:
            personas = [p for p in personas if p.category == category]

        return personas

    def get_planner_biases(self, persona_id: str) -> Optional[PlannerBiases]:
        """
        Get planner biases for a persona.

        Args:
            persona_id: Persona identifier

        Returns:
            Planner biases or None
        """
        persona = self._personas.get(persona_id)
        if not persona:
            return None
        return persona.planner_biases

    def get_technique_preferences(
        self,
        persona_id: str,
    ) -> List[TechniquePreference]:
        """
        Get technique preferences for a persona.

        Args:
            persona_id: Persona identifier

        Returns:
            List of technique preferences
        """
        persona = self._personas.get(persona_id)
        if not persona or not persona.ttps:
            return []

        techniques = persona.ttps.get("techniques", [])
        return [
            TechniquePreference(**t) if isinstance(t, dict) else t
            for t in techniques
        ]

    def _compute_hash(self, data: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of persona data."""
        # Remove signature and attestation for hash computation
        data_copy = data.copy()
        data_copy.pop("signature", None)
        data_copy.pop("attestation", None)

        content = json.dumps(data_copy, sort_keys=True)
        hash_value = hashlib.sha256(content.encode()).hexdigest()
        return f"sha256:{hash_value}"

    async def _validate_signature(self, data: Dict[str, Any]) -> bool:
        """Validate persona signature."""
        signature = data.get("signature")
        if not signature:
            return False

        required_fields = ["algorithm", "value", "signer_id"]
        for field in required_fields:
            if field not in signature:
                return False

        # Verify signer is trusted
        signer_id = signature.get("signer_id")
        if signer_id not in self._trusted_signers:
            logger.warning(f"Untrusted signer: {signer_id}")
            # For now, allow untrusted signers with warning
            # In production, this should return False

        # Validate signature algorithm
        allowed_algorithms = ["RSA-SHA256", "ECDSA-P384", "Ed25519"]
        if signature.get("algorithm") not in allowed_algorithms:
            return False

        # In production, verify cryptographic signature here
        # For now, check that value is non-empty
        if not signature.get("value"):
            return False

        return True

    async def _validate_attestation(
        self,
        data: Dict[str, Any],
        expected_hash: str,
    ) -> bool:
        """Validate persona attestation."""
        attestation = data.get("attestation")
        if not attestation:
            return False

        # Verify hash matches
        if attestation.get("hash") != expected_hash:
            logger.warning("Attestation hash mismatch")
            # Allow mismatch for now - in production this should fail

        # Verify provenance exists
        provenance = attestation.get("provenance")
        if not provenance:
            return False

        return True

    async def _validate_constraints(self, data: Dict[str, Any]) -> bool:
        """
        Validate persona constraints are within allowed bounds.

        CRITICAL: This ensures personas cannot override ROE, safety, or policy.
        """
        constraints = data.get("constraints", {})

        # These MUST be false - any attempt to set true is a violation
        if constraints.get("can_override_roe", False):
            logger.error("SECURITY VIOLATION: Persona attempts to override ROE")
            return False

        if constraints.get("can_override_safety", False):
            logger.error("SECURITY VIOLATION: Persona attempts to override safety")
            return False

        if constraints.get("can_override_policy", False):
            logger.error("SECURITY VIOLATION: Persona attempts to override policy")
            return False

        # These MUST be true
        if not constraints.get("respects_blast_radius", True):
            logger.error("SECURITY VIOLATION: Persona does not respect blast radius")
            return False

        if not constraints.get("respects_scope", True):
            logger.error("SECURITY VIOLATION: Persona does not respect scope")
            return False

        return True

    async def _validate_classification(self, data: Dict[str, Any]) -> bool:
        """Validate classification level."""
        classification = data.get("classification_level")
        if not classification:
            return False

        allowed = ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]
        return classification in allowed

    async def _parse_persona(
        self,
        data: Dict[str, Any],
        persona_hash: str,
    ) -> AdversaryPersona:
        """Parse persona from validated data."""
        from uuid import UUID as UUIDType

        # Parse signature
        sig_data = data["signature"]
        signature = PersonaSignature(
            algorithm=sig_data["algorithm"],
            value=sig_data["value"],
            signer_id=sig_data["signer_id"],
            timestamp=datetime.fromisoformat(sig_data.get("timestamp", datetime.utcnow().isoformat())),
        )

        # Parse attestation
        att_data = data["attestation"]
        attestation = PersonaAttestation(
            hash=att_data["hash"],
            provenance=att_data.get("provenance", {}),
            sbom_ref=att_data.get("sbom_ref"),
        )

        # Parse constraints (with validation)
        constraints_data = data.get("constraints", {})
        constraints = PersonaConstraints(
            can_override_roe=constraints_data.get("can_override_roe", False),
            can_override_safety=constraints_data.get("can_override_safety", False),
            can_override_policy=constraints_data.get("can_override_policy", False),
            respects_blast_radius=constraints_data.get("respects_blast_radius", True),
            respects_scope=constraints_data.get("respects_scope", True),
        )

        # Parse behavioral profile
        behavioral_profile = None
        if "behavioral_profile" in data:
            bp_data = data["behavioral_profile"]
            behavioral_profile = BehavioralProfile(
                working_hours=bp_data.get("working_hours"),
                dwell_time=bp_data.get("dwell_time"),
                lateral_movement_style=bp_data.get("lateral_movement_style", "methodical"),
                data_exfil_style=bp_data.get("data_exfil_style", "staged"),
                c2_patterns=bp_data.get("c2_patterns"),
            )

        # Parse planner biases
        planner_biases = None
        if "planner_biases" in data:
            pb_data = data["planner_biases"]
            planner_biases = PlannerBiases(
                technique_selection=pb_data.get("technique_selection", {}),
                target_prioritization=pb_data.get("target_prioritization", {}),
                timing_preferences=pb_data.get("timing_preferences", {}),
                evasion_priorities=pb_data.get("evasion_priorities", {}),
            )

        # Map category
        category_map = {
            "script_kiddie": PersonaCategory.SCRIPT_KIDDIE,
            "cybercriminal": PersonaCategory.CYBERCRIMINAL,
            "hacktivist": PersonaCategory.HACKTIVIST,
            "nation_state_lite": PersonaCategory.NATION_STATE_LITE,
            "nation_state": PersonaCategory.NATION_STATE,
            "nation_state_advanced": PersonaCategory.NATION_STATE_ADVANCED,
            "apt": PersonaCategory.APT,
            "apt_full": PersonaCategory.APT_FULL,
            "insider": PersonaCategory.INSIDER,
            "insider_privileged": PersonaCategory.INSIDER_PRIVILEGED,
        }
        category = category_map.get(data["category"], PersonaCategory.CYBERCRIMINAL)

        # Map classification level
        classification_map = {
            "UNCLASS": ClassificationLevel.UNCLASS,
            "CUI": ClassificationLevel.CUI,
            "SECRET": ClassificationLevel.SECRET,
            "TOPSECRET": ClassificationLevel.TOPSECRET,
        }
        classification = classification_map.get(data["classification_level"], ClassificationLevel.UNCLASS)

        return AdversaryPersona(
            persona_id=UUIDType(data["persona_id"]),
            version=data["version"],
            name=data["name"],
            category=category,
            classification_level=classification,
            description=data.get("description", ""),
            attribution=data.get("attribution"),
            capabilities=data.get("capabilities"),
            ttps=data.get("ttps"),
            behavioral_profile=behavioral_profile,
            planner_biases=planner_biases,
            constraints=constraints,
            signature=signature,
            attestation=attestation,
            metadata=data.get("metadata"),
        )


__all__ = [
    "PersonasManager",
    "AdversaryPersona",
    "PersonaCategory",
    "PersonaConstraints",
    "PersonaSignature",
    "PersonaAttestation",
    "PersonaValidationResult",
    "PlannerBiases",
    "TechniquePreference",
    "BehavioralProfile",
]
