"""
Frost Gate Spear - Federated Learning Controller

Ring-isolated federated learning for model improvement.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.exceptions import MLSViolationError

logger = logging.getLogger(__name__)


@dataclass
class FLRound:
    """Federated learning round."""
    round_id: UUID
    round_number: int
    ring: str
    participants: int
    aggregation_method: str
    dp_epsilon: float
    dp_delta: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    metrics: Optional[Dict[str, float]] = None


@dataclass
class ModelUpdate:
    """Model update from FL round."""
    update_id: UUID
    model_id: str
    model_version: str
    ring: str
    round_id: UUID
    metrics: Dict[str, float]
    lineage_hash: str
    timestamp: datetime


class FLController:
    """
    Federated Learning Controller.

    Manages:
    - Ring-isolated FL training
    - Differential privacy enforcement
    - Secure aggregation
    - Cross-ring gradient isolation
    - Model lineage tracking
    """

    def __init__(self, config: Config):
        """Initialize FL Controller."""
        self.config = config
        self._rounds: Dict[str, List[FLRound]] = {}  # Per-ring rounds
        self._models: Dict[str, Dict] = {}
        self._active_rounds: Dict[str, FLRound] = {}

    async def start(self) -> None:
        """Start FL Controller."""
        logger.info("Starting FL Controller...")
        if self.config.fl.enabled:
            await self._initialize_rings()
        logger.info("FL Controller started")

    async def stop(self) -> None:
        """Stop FL Controller."""
        logger.info("Stopping FL Controller...")
        # Finalize any active rounds
        for ring, round_obj in self._active_rounds.items():
            await self._finalize_round(round_obj)

    async def _initialize_rings(self) -> None:
        """Initialize FL for each ring."""
        rings = ["UNCLASS", "CUI"]  # Active FL rings
        for ring in rings:
            self._rounds[ring] = []

    async def start_round(
        self,
        ring: str,
        model_id: str,
        participants: List[str],
    ) -> FLRound:
        """
        Start a new FL round.

        Args:
            ring: Classification ring
            model_id: Model to train
            participants: Participating clients

        Returns:
            Started FL round
        """
        if len(participants) < self.config.fl.min_participants:
            raise ValueError(
                f"Insufficient participants: {len(participants)} < {self.config.fl.min_participants}"
            )

        round_number = len(self._rounds.get(ring, [])) + 1

        fl_round = FLRound(
            round_id=uuid4(),
            round_number=round_number,
            ring=ring,
            participants=len(participants),
            aggregation_method=self.config.fl.default_aggregation,
            dp_epsilon=self.config.fl.default_epsilon,
            dp_delta=self.config.fl.default_delta,
            started_at=datetime.utcnow(),
        )

        self._active_rounds[ring] = fl_round

        if ring not in self._rounds:
            self._rounds[ring] = []
        self._rounds[ring].append(fl_round)

        logger.info(f"Started FL round {round_number} in ring {ring}")
        return fl_round

    async def submit_gradient(
        self,
        round_id: UUID,
        participant_id: str,
        gradient: Dict[str, Any],
        ring: str,
    ) -> bool:
        """
        Submit gradient update from participant.

        Args:
            round_id: FL round ID
            participant_id: Participant submitting
            gradient: Gradient update
            ring: Participant's ring

        Returns:
            True if accepted
        """
        # Verify ring isolation
        active_round = self._active_rounds.get(ring)
        if not active_round or active_round.round_id != round_id:
            raise MLSViolationError(
                "Gradient submitted to wrong ring",
                source_ring=ring,
                operation="gradient_submit",
            )

        # Apply differential privacy
        if self.config.fl.differential_privacy_enabled:
            gradient = await self._apply_dp(gradient, active_round)

        # Store gradient for aggregation
        # In production, this would use secure aggregation protocols
        logger.debug(f"Gradient received from {participant_id} in ring {ring}")
        return True

    async def aggregate(self, round_id: UUID, ring: str) -> ModelUpdate:
        """
        Aggregate gradients and update model.

        Args:
            round_id: FL round to aggregate
            ring: Ring to aggregate in

        Returns:
            Model update result
        """
        active_round = self._active_rounds.get(ring)
        if not active_round or active_round.round_id != round_id:
            raise ValueError("Invalid round for aggregation")

        # Perform aggregation based on method
        if active_round.aggregation_method == "fedavg":
            metrics = await self._fedavg_aggregate(ring)
        elif active_round.aggregation_method == "secure_aggregation":
            metrics = await self._secure_aggregate(ring)
        else:
            metrics = await self._fedavg_aggregate(ring)

        # Finalize round
        active_round.completed_at = datetime.utcnow()
        active_round.metrics = metrics

        # Create model update
        update = ModelUpdate(
            update_id=uuid4(),
            model_id=f"model_{ring.lower()}",
            model_version=f"v{active_round.round_number}",
            ring=ring,
            round_id=round_id,
            metrics=metrics,
            lineage_hash=self._compute_lineage_hash(active_round),
            timestamp=datetime.utcnow(),
        )

        del self._active_rounds[ring]

        logger.info(f"Aggregation complete for round {active_round.round_number} in {ring}")
        return update

    async def validate_cross_ring_sharing(
        self,
        source_ring: str,
        dest_ring: str,
        data_type: str,
    ) -> bool:
        """
        Validate cross-ring data sharing is allowed.

        Args:
            source_ring: Source classification ring
            dest_ring: Destination ring
            data_type: Type of data (gradient, model, etc.)

        Returns:
            True if sharing allowed
        """
        # Gradients never cross rings without DP
        if data_type == "gradient":
            raise MLSViolationError(
                "Raw gradients cannot cross ring boundaries",
                source_ring=source_ring,
                target_ring=dest_ring,
                operation="cross_ring_share",
            )

        # Models can only go to same or higher classification
        ring_levels = {"UNCLASS": 0, "CUI": 1, "SECRET": 2, "TOPSECRET": 3}

        source_level = ring_levels.get(source_ring, 0)
        dest_level = ring_levels.get(dest_ring, 0)

        if dest_level < source_level:
            raise MLSViolationError(
                f"Cannot share model from {source_ring} to {dest_ring}",
                source_ring=source_ring,
                target_ring=dest_ring,
                operation="model_share",
            )

        return True

    async def get_ring_metrics(self, ring: str) -> Dict[str, Any]:
        """Get FL metrics for a ring."""
        rounds = self._rounds.get(ring, [])

        if not rounds:
            return {"ring": ring, "rounds": 0, "metrics": {}}

        # Aggregate metrics across rounds
        total_participants = sum(r.participants for r in rounds)
        avg_participants = total_participants / len(rounds)

        completed_rounds = [r for r in rounds if r.completed_at]

        return {
            "ring": ring,
            "total_rounds": len(rounds),
            "completed_rounds": len(completed_rounds),
            "average_participants": avg_participants,
            "dp_epsilon_used": sum(r.dp_epsilon for r in completed_rounds),
            "latest_round": rounds[-1].round_number if rounds else 0,
        }

    async def _apply_dp(
        self, gradient: Dict[str, Any], fl_round: FLRound
    ) -> Dict[str, Any]:
        """Apply differential privacy to gradient."""
        # In production, this would add calibrated noise
        # For now, return gradient with DP marker
        return {
            **gradient,
            "dp_applied": True,
            "dp_epsilon": fl_round.dp_epsilon,
            "dp_delta": fl_round.dp_delta,
        }

    async def _fedavg_aggregate(self, ring: str) -> Dict[str, float]:
        """Perform FedAvg aggregation."""
        # In production, this would aggregate actual gradients
        return {
            "loss": 0.15,
            "accuracy": 0.92,
            "aggregation_method": "fedavg",
        }

    async def _secure_aggregate(self, ring: str) -> Dict[str, float]:
        """Perform secure aggregation."""
        # In production, this would use MPC-based secure aggregation
        return {
            "loss": 0.14,
            "accuracy": 0.93,
            "aggregation_method": "secure_aggregation",
        }

    async def _finalize_round(self, fl_round: FLRound) -> None:
        """Finalize an FL round."""
        if not fl_round.completed_at:
            fl_round.completed_at = datetime.utcnow()
            logger.info(f"Finalized FL round {fl_round.round_number}")

    def _compute_lineage_hash(self, fl_round: FLRound) -> str:
        """Compute lineage hash for FL round."""
        import hashlib
        import json

        data = {
            "round_id": str(fl_round.round_id),
            "round_number": fl_round.round_number,
            "ring": fl_round.ring,
            "participants": fl_round.participants,
            "dp_epsilon": fl_round.dp_epsilon,
        }

        content = json.dumps(data, sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
