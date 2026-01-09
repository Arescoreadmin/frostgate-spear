"""
Frost Gate Spear - Multi-Level Security (MLS) Manager

Classification ring management and cross-ring data flow control.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..core.config import Config, ClassificationLevel
from ..core.exceptions import MLSViolationError

logger = logging.getLogger(__name__)


@dataclass
class RingConfig:
    """Configuration for a classification ring."""
    name: str
    level: int
    enclave_config: Dict[str, Any]
    operations: Dict[str, Any]
    data_handling: Dict[str, Any]
    audit_config: Dict[str, Any]
    promotion_requirements: Dict[str, Any]


@dataclass
class DataFlowRequest:
    """Request for cross-ring data flow."""
    source_ring: str
    dest_ring: str
    data_type: str
    sanitized: bool
    declassification_authorized: bool
    requestor: str
    timestamp: datetime


class MLSManager:
    """
    Multi-Level Security Manager.

    Enforces:
    - Classification ring isolation
    - Bell-LaPadula model (no read up, no write down)
    - Cross-ring data flow controls
    - Artifact labeling
    - Gradient isolation for FL
    """

    def __init__(self, config: Config):
        """Initialize MLS Manager."""
        self.config = config
        self._rings: Dict[str, RingConfig] = {}
        self._current_ring: Optional[str] = None

    async def start(self) -> None:
        """Start MLS Manager."""
        logger.info("Starting MLS Manager...")
        await self._load_ring_configs()
        self._current_ring = self.config.mls.default_ring.value
        logger.info(f"MLS Manager started. Current ring: {self._current_ring}")

    async def stop(self) -> None:
        """Stop MLS Manager."""
        logger.info("Stopping MLS Manager...")

    async def _load_ring_configs(self) -> None:
        """Load ring configurations from files."""
        base_path = Path(self.config.base_path)

        for ring_name, config_path in self.config.mls.ring_configs.items():
            full_path = base_path / config_path

            if full_path.exists():
                with open(full_path) as f:
                    ring_data = yaml.safe_load(f)

                self._rings[ring_name] = RingConfig(
                    name=ring_data.get("ring", {}).get("name", ring_name),
                    level=ring_data.get("ring", {}).get("level", 0),
                    enclave_config=ring_data.get("enclave", {}),
                    operations=ring_data.get("operations", {}),
                    data_handling=ring_data.get("data", {}),
                    audit_config=ring_data.get("audit", {}),
                    promotion_requirements=ring_data.get("promotion", {}),
                )
                logger.info(f"Loaded ring config: {ring_name}")
            else:
                logger.warning(f"Ring config not found: {config_path}")

    async def validate_rings(self) -> None:
        """Validate ring configurations."""
        if not self._rings:
            raise MLSViolationError(
                "No ring configurations loaded",
                operation="validate_rings",
            )

        # Verify ring hierarchy
        levels = [(name, ring.level) for name, ring in self._rings.items()]
        levels.sort(key=lambda x: x[1])

        for i in range(len(levels) - 1):
            if levels[i][1] >= levels[i + 1][1]:
                raise MLSViolationError(
                    f"Invalid ring hierarchy: {levels[i][0]} >= {levels[i + 1][0]}",
                    operation="validate_rings",
                )

    async def validate_ring_access(self, classification: str) -> bool:
        """
        Validate access to classification ring.

        Args:
            classification: Requested classification level

        Returns:
            True if access allowed

        Raises:
            MLSViolationError: If access denied
        """
        if classification not in self._rings:
            raise MLSViolationError(
                f"Unknown classification level: {classification}",
                target_ring=classification,
                operation="access",
            )

        current_level = self._get_ring_level(self._current_ring)
        requested_level = self._get_ring_level(classification)

        # Can access same or lower level
        if requested_level > current_level:
            raise MLSViolationError(
                f"Insufficient clearance for {classification}",
                source_ring=self._current_ring,
                target_ring=classification,
                operation="access",
            )

        return True

    async def validate_read(
        self,
        subject_classification: str,
        object_classification: str,
    ) -> bool:
        """
        Validate read operation (Bell-LaPadula: no read up).

        Args:
            subject_classification: Reader's classification
            object_classification: Object's classification

        Returns:
            True if read allowed
        """
        subject_level = self._get_ring_level(subject_classification)
        object_level = self._get_ring_level(object_classification)

        if subject_level < object_level:
            raise MLSViolationError(
                f"Read up violation: {subject_classification} cannot read {object_classification}",
                source_ring=subject_classification,
                target_ring=object_classification,
                operation="read",
            )

        return True

    async def validate_write(
        self,
        subject_classification: str,
        object_classification: str,
        declassification_authorized: bool = False,
    ) -> bool:
        """
        Validate write operation (Bell-LaPadula: no write down).

        Args:
            subject_classification: Writer's classification
            object_classification: Target object's classification
            declassification_authorized: Whether declassification is authorized

        Returns:
            True if write allowed
        """
        subject_level = self._get_ring_level(subject_classification)
        object_level = self._get_ring_level(object_classification)

        if subject_level > object_level:
            if not declassification_authorized:
                raise MLSViolationError(
                    f"Write down violation: {subject_classification} cannot write to {object_classification}",
                    source_ring=subject_classification,
                    target_ring=object_classification,
                    operation="write",
                )

        return True

    async def validate_data_flow(self, request: DataFlowRequest) -> bool:
        """
        Validate cross-ring data flow request.

        Args:
            request: Data flow request

        Returns:
            True if flow allowed
        """
        source_level = self._get_ring_level(request.source_ring)
        dest_level = self._get_ring_level(request.dest_ring)

        # Same ring is always OK
        if source_level == dest_level:
            return True

        # Upgrade (lower to higher) is generally allowed
        if source_level < dest_level:
            return True

        # Downgrade requires authorization and sanitization
        if source_level > dest_level:
            if not request.declassification_authorized:
                raise MLSViolationError(
                    "Declassification not authorized for data flow",
                    source_ring=request.source_ring,
                    target_ring=request.dest_ring,
                    operation="data_flow",
                )

            if not request.sanitized:
                raise MLSViolationError(
                    "Data must be sanitized for downgrade",
                    source_ring=request.source_ring,
                    target_ring=request.dest_ring,
                    operation="data_flow",
                )

        return True

    async def validate_gradient_flow(
        self,
        source_ring: str,
        dest_ring: str,
        dp_applied: bool,
        dp_epsilon: float,
    ) -> bool:
        """
        Validate FL gradient flow between rings.

        Args:
            source_ring: Source classification ring
            dest_ring: Destination classification ring
            dp_applied: Whether differential privacy is applied
            dp_epsilon: DP epsilon value if applied

        Returns:
            True if gradient flow allowed
        """
        if source_ring == dest_ring:
            return True

        if not self.config.mls.cross_ring_enabled:
            raise MLSViolationError(
                "Cross-ring gradient flow disabled",
                source_ring=source_ring,
                target_ring=dest_ring,
                operation="gradient_flow",
            )

        # Gradients require DP for cross-ring flow
        if not dp_applied:
            raise MLSViolationError(
                "Differential privacy required for cross-ring gradient flow",
                source_ring=source_ring,
                target_ring=dest_ring,
                operation="gradient_flow",
            )

        # Check epsilon bounds based on rings
        ring_config = self._rings.get(source_ring)
        if ring_config:
            fl_config = ring_config.data_handling.get("fl", {})
            max_epsilon = fl_config.get("max_epsilon", 1.0)

            if dp_epsilon > max_epsilon:
                raise MLSViolationError(
                    f"DP epsilon {dp_epsilon} exceeds maximum {max_epsilon}",
                    source_ring=source_ring,
                    target_ring=dest_ring,
                    operation="gradient_flow",
                )

        return True

    async def label_artifact(
        self,
        artifact: Dict[str, Any],
        classification: str,
    ) -> Dict[str, Any]:
        """
        Label artifact with classification.

        Args:
            artifact: Artifact to label
            classification: Classification level

        Returns:
            Labeled artifact
        """
        if classification not in self._rings:
            raise MLSViolationError(
                f"Invalid classification: {classification}",
                operation="label",
            )

        ring_config = self._rings[classification]
        data_config = ring_config.data_handling

        artifact["classification"] = {
            "level": classification,
            "label": data_config.get("classification_label", classification),
            "banner": data_config.get("banner", ""),
            "marking_required": data_config.get("marking_required", True),
            "labeled_at": datetime.utcnow().isoformat(),
        }

        return artifact

    async def get_ring_config(self, ring_name: str) -> Optional[RingConfig]:
        """Get configuration for a ring."""
        return self._rings.get(ring_name)

    async def get_promotion_requirements(
        self, ring_name: str, target_env: str
    ) -> Dict[str, Any]:
        """
        Get requirements for promoting to an environment within a ring.

        Args:
            ring_name: Classification ring
            target_env: Target environment (lab, canary, production, mission)

        Returns:
            Promotion requirements
        """
        ring_config = self._rings.get(ring_name)
        if not ring_config:
            return {}

        promotion = ring_config.promotion_requirements
        return promotion.get(f"to_{target_env}", {})

    async def validate_enclave_isolation(self, ring_name: str) -> Dict[str, bool]:
        """
        Validate enclave isolation for a ring.

        Args:
            ring_name: Ring to validate

        Returns:
            Isolation status dictionary
        """
        ring_config = self._rings.get(ring_name)
        if not ring_config:
            return {"valid": False, "error": "Ring not found"}

        enclave = ring_config.enclave_config.get("isolation", {})

        return {
            "network_isolated": enclave.get("network", {}).get("enabled", False),
            "process_isolated": enclave.get("process", {}).get("enabled", False),
            "storage_isolated": enclave.get("storage", {}).get("enabled", False),
            "valid": all([
                enclave.get("network", {}).get("enabled", False),
                enclave.get("process", {}).get("enabled", False),
                enclave.get("storage", {}).get("enabled", False),
            ]),
        }

    def _get_ring_level(self, ring_name: str) -> int:
        """Get numeric level for a ring."""
        ring = self._rings.get(ring_name)
        if ring:
            return ring.level

        # Default levels if not configured
        default_levels = {
            "UNCLASS": 0,
            "CUI": 1,
            "SECRET": 2,
            "TOPSECRET": 3,
        }
        return default_levels.get(ring_name, 0)

    def get_current_ring(self) -> str:
        """Get current operating ring."""
        return self._current_ring or "UNCLASS"

    async def set_ring(self, ring_name: str) -> None:
        """Set current operating ring."""
        if ring_name not in self._rings:
            raise MLSViolationError(
                f"Unknown ring: {ring_name}",
                target_ring=ring_name,
                operation="set_ring",
            )
        self._current_ring = ring_name
        logger.info(f"Set current ring to: {ring_name}")
