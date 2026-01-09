"""
Frost Gate Spear - Target Impact Estimator (TIE)

Estimates and tracks operational impact of missions.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.config import Config
from ..core.exceptions import BlastRadiusExceededError

logger = logging.getLogger(__name__)


@dataclass
class ImpactEstimate:
    """Impact estimation result."""
    score: float  # 0-100 scale
    confidence: float  # 0-1 confidence in estimate
    breakdown: Dict[str, float]
    exceeds_blast_radius: bool
    blast_radius_cap: float
    timestamp: datetime
    methodology: str


@dataclass
class ImpactFactors:
    """Factors contributing to impact score."""
    target_criticality: float = 0.0
    action_severity: float = 0.0
    scope_breadth: float = 0.0
    persistence_depth: float = 0.0
    data_sensitivity: float = 0.0
    service_disruption: float = 0.0
    detection_likelihood: float = 0.0


class TargetImpactEstimator:
    """
    Target Impact Estimator (TIE).

    Estimates operational impact including:
    - Target criticality assessment
    - Action severity scoring
    - Blast radius prediction
    - Cumulative impact tracking
    - ML-based impact prediction
    """

    def __init__(self, config: Config):
        """Initialize TIE."""
        self.config = config
        self._model = None
        self._criticality_map: Dict[str, float] = {}
        self._action_severity: Dict[str, float] = {}

    async def start(self) -> None:
        """Start the TIE."""
        logger.info("Starting Target Impact Estimator...")
        await self._load_models()
        self._initialize_scoring_maps()
        logger.info("Target Impact Estimator started")

    async def stop(self) -> None:
        """Stop the TIE."""
        logger.info("Stopping Target Impact Estimator...")

    async def _load_models(self) -> None:
        """Load ML models for impact prediction."""
        if self.config.tie.enable_ml_predictions:
            # In production, load trained model
            pass

    def _initialize_scoring_maps(self) -> None:
        """Initialize criticality and severity scoring maps."""
        # Target criticality scores (0-1)
        self._criticality_map = {
            "domain_controller": 1.0,
            "pki_server": 0.95,
            "database_server": 0.9,
            "file_server": 0.7,
            "web_server": 0.6,
            "workstation": 0.3,
            "printer": 0.1,
            "iot_device": 0.2,
            "scada": 1.0,
            "ics": 0.95,
            "medical_device": 1.0,
            "safety_system": 1.0,
        }

        # Action severity scores (0-1)
        self._action_severity = {
            "reconnaissance": 0.1,
            "vulnerability_scan": 0.2,
            "exploitation": 0.6,
            "credential_access": 0.7,
            "lateral_movement": 0.7,
            "privilege_escalation": 0.8,
            "persistence": 0.7,
            "data_exfiltration": 0.9,
            "data_destruction": 1.0,
            "service_disruption": 0.9,
            "ransomware": 1.0,
        }

    async def estimate_impact(self, mission: Any) -> ImpactEstimate:
        """
        Estimate overall mission impact.

        Args:
            mission: Mission to estimate impact for

        Returns:
            Impact estimate
        """
        factors = await self._calculate_factors(mission)
        score = self._compute_score(factors)

        blast_radius_cap = self._get_blast_radius_cap(mission)
        exceeds = score > blast_radius_cap

        estimate = ImpactEstimate(
            score=score,
            confidence=self._compute_confidence(factors),
            breakdown={
                "target_criticality": factors.target_criticality * 20,
                "action_severity": factors.action_severity * 25,
                "scope_breadth": factors.scope_breadth * 15,
                "persistence_depth": factors.persistence_depth * 15,
                "data_sensitivity": factors.data_sensitivity * 15,
                "service_disruption": factors.service_disruption * 10,
            },
            exceeds_blast_radius=exceeds,
            blast_radius_cap=blast_radius_cap,
            timestamp=datetime.utcnow(),
            methodology="weighted_factors_v1",
        )

        if exceeds:
            logger.warning(
                f"Impact estimate {score} exceeds blast radius cap {blast_radius_cap}"
            )

        return estimate

    async def estimate_action_impact(
        self,
        action: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ImpactEstimate:
        """
        Estimate impact of a single action.

        Args:
            action: Action to estimate
            context: Additional context

        Returns:
            Impact estimate
        """
        context = context or {}

        # Get target criticality
        target = action.get("target", {})
        target_type = target.get("type", "unknown")
        criticality = self._criticality_map.get(target_type, 0.5)

        # Get action severity
        action_type = action.get("type", "unknown")
        severity = self._action_severity.get(action_type, 0.5)

        # Compute score
        base_score = (criticality * 0.4 + severity * 0.6) * 100

        # Apply modifiers
        if action.get("destructive"):
            base_score *= 1.5

        if target.get("criticality") == "high":
            base_score *= 1.3

        score = min(base_score, 100)

        blast_radius_cap = context.get("blast_radius_cap", 100)

        return ImpactEstimate(
            score=score,
            confidence=0.8,
            breakdown={
                "target_criticality": criticality * 40,
                "action_severity": severity * 60,
            },
            exceeds_blast_radius=score > blast_radius_cap,
            blast_radius_cap=blast_radius_cap,
            timestamp=datetime.utcnow(),
            methodology="single_action_v1",
        )

    async def update_impact(
        self, mission: Any, action_result: Any
    ) -> float:
        """
        Update cumulative impact after action execution.

        Args:
            mission: Mission being executed
            action_result: Result of executed action

        Returns:
            Updated cumulative impact score
        """
        # Estimate action impact
        action_impact = await self.estimate_action_impact(
            {
                "type": action_result.action_type,
                "target": {"asset": action_result.target},
            }
        )

        # Update cumulative with diminishing returns
        current_impact = mission.impact_score
        new_contribution = action_impact.score * 0.1  # Actions contribute incrementally

        updated_impact = min(current_impact + new_contribution, 100)

        # Check blast radius
        blast_radius_cap = self._get_blast_radius_cap(mission)
        if updated_impact > blast_radius_cap:
            raise BlastRadiusExceededError(
                f"Impact {updated_impact} exceeds blast radius cap {blast_radius_cap}",
                estimated_impact=updated_impact,
                blast_radius_cap=blast_radius_cap,
            )

        return updated_impact

    async def _calculate_factors(self, mission: Any) -> ImpactFactors:
        """Calculate impact factors for mission."""
        factors = ImpactFactors()

        scenario = mission.scenario

        # Target criticality
        targets = scenario.get("targets", [])
        if targets:
            criticalities = [
                self._criticality_map.get(t.get("type"), 0.5) for t in targets
            ]
            factors.target_criticality = max(criticalities)

        # Action severity
        phases = scenario.get("phases", [])
        severities = []
        for phase in phases:
            for action in phase.get("actions", []):
                severity = self._action_severity.get(action.get("type"), 0.5)
                severities.append(severity)

        if severities:
            factors.action_severity = max(severities)

        # Scope breadth
        factors.scope_breadth = min(len(targets) / 10, 1.0)

        # Persistence depth
        has_persistence = any(
            action.get("type") == "persistence"
            for phase in phases
            for action in phase.get("actions", [])
        )
        factors.persistence_depth = 1.0 if has_persistence else 0.0

        # Data sensitivity
        roe = mission.policy_envelope.get("roe", {})
        if roe.get("data_exfiltration_authorized"):
            factors.data_sensitivity = 0.8

        # Service disruption
        has_disruption = any(
            action.get("type") in ["service_disruption", "ransomware"]
            for phase in phases
            for action in phase.get("actions", [])
        )
        factors.service_disruption = 1.0 if has_disruption else 0.0

        return factors

    def _compute_score(self, factors: ImpactFactors) -> float:
        """Compute overall impact score from factors."""
        weights = {
            "target_criticality": 0.25,
            "action_severity": 0.25,
            "scope_breadth": 0.15,
            "persistence_depth": 0.10,
            "data_sensitivity": 0.15,
            "service_disruption": 0.10,
        }

        score = (
            factors.target_criticality * weights["target_criticality"]
            + factors.action_severity * weights["action_severity"]
            + factors.scope_breadth * weights["scope_breadth"]
            + factors.persistence_depth * weights["persistence_depth"]
            + factors.data_sensitivity * weights["data_sensitivity"]
            + factors.service_disruption * weights["service_disruption"]
        )

        return score * 100  # Scale to 0-100

    def _compute_confidence(self, factors: ImpactFactors) -> float:
        """Compute confidence in impact estimate."""
        # Higher confidence when factors are well-defined
        defined_factors = sum(
            1 for v in [
                factors.target_criticality,
                factors.action_severity,
                factors.scope_breadth,
            ]
            if v > 0
        )

        base_confidence = 0.5 + (defined_factors / 6) * 0.5

        return min(base_confidence, 0.95)

    def _get_blast_radius_cap(self, mission: Any) -> float:
        """Get blast radius cap from mission policy."""
        roe = mission.policy_envelope.get("roe", {})
        return roe.get("blast_radius_cap", self.config.tie.default_blast_radius_cap)

    async def predict_impact_ml(
        self, mission: Any
    ) -> Optional[ImpactEstimate]:
        """
        Use ML model for impact prediction.

        Args:
            mission: Mission to predict impact for

        Returns:
            ML-based impact estimate or None if model unavailable
        """
        if not self._model:
            return None

        # In production, this would use the trained model
        # For now, fall back to rule-based estimation
        return await self.estimate_impact(mission)
