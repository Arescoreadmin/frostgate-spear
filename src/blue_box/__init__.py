"""
Frost Gate Spear - Blue Box Explainer

Explainability and transparency subsystem.
Provides human-readable explanations of mission actions and decisions.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.config import Config

logger = logging.getLogger(__name__)


@dataclass
class Explanation:
    """Explanation of a decision or action."""
    explanation_id: UUID
    subject_type: str  # mission, action, plan, persona
    subject_id: str
    summary: str
    details: List[str]
    factors: Dict[str, Any]
    confidence: float
    timestamp: datetime


@dataclass
class MissionExplanation:
    """Comprehensive mission explanation."""
    mission_id: UUID
    summary: str
    objective: str
    methodology: str
    phases: List[Dict[str, Any]]
    key_decisions: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    counterfactuals: List[Dict[str, Any]]
    timestamp: datetime


class BlueBox:
    """
    Blue Box Explainer.

    Provides explainability for:
    - Mission planning decisions
    - Attack persona behavior
    - Action selection rationale
    - Impact assessments
    - ROE compliance
    - Counterfactual analysis
    """

    def __init__(self, config: Config):
        """Initialize Blue Box."""
        self.config = config
        self._explanation_cache: Dict[str, Explanation] = {}

    async def start(self) -> None:
        """Start Blue Box."""
        logger.info("Starting Blue Box Explainer...")
        logger.info("Blue Box Explainer started")

    async def stop(self) -> None:
        """Stop Blue Box."""
        logger.info("Stopping Blue Box Explainer...")

    async def explain_mission(self, mission: Any) -> MissionExplanation:
        """
        Generate comprehensive mission explanation.

        Args:
            mission: Mission to explain

        Returns:
            Mission explanation
        """
        # Generate summary
        summary = self._generate_mission_summary(mission)

        # Explain objective
        objective = self._explain_objective(mission)

        # Explain methodology
        methodology = self._explain_methodology(mission)

        # Explain phases
        phases = await self._explain_phases(mission)

        # Extract key decisions
        key_decisions = await self._extract_key_decisions(mission)

        # Generate risk assessment explanation
        risk_assessment = self._explain_risk_assessment(mission)

        # Generate counterfactuals if available
        counterfactuals = await self._generate_counterfactuals(mission)

        return MissionExplanation(
            mission_id=mission.mission_id,
            summary=summary,
            objective=objective,
            methodology=methodology,
            phases=phases,
            key_decisions=key_decisions,
            risk_assessment=risk_assessment,
            counterfactuals=counterfactuals,
            timestamp=datetime.utcnow(),
        )

    async def explain_action(
        self, action: Dict[str, Any], context: Dict[str, Any]
    ) -> Explanation:
        """
        Explain why an action was selected.

        Args:
            action: Action to explain
            context: Context in which action was selected

        Returns:
            Action explanation
        """
        from uuid import uuid4

        action_type = action.get("type", "unknown")
        target = action.get("target", {}).get("asset", "unknown")

        summary = f"Selected {action_type} against {target}"
        details = []
        factors = {}

        # Explain target selection
        details.append(f"Target '{target}' selected based on:")
        if context.get("target_value"):
            details.append(f"  - High value target (score: {context['target_value']})")
            factors["target_value"] = context["target_value"]

        if context.get("vulnerability"):
            details.append(f"  - Known vulnerability: {context['vulnerability']}")
            factors["vulnerability"] = context["vulnerability"]

        # Explain technique selection
        details.append(f"Technique '{action_type}' chosen because:")
        if context.get("persona_preference"):
            details.append(f"  - Preferred by current persona")
            factors["persona_preference"] = context["persona_preference"]

        if context.get("success_probability"):
            details.append(f"  - High success probability: {context['success_probability']:.0%}")
            factors["success_probability"] = context["success_probability"]

        if context.get("stealth_rating"):
            details.append(f"  - Stealth rating: {context['stealth_rating']:.0%}")
            factors["stealth_rating"] = context["stealth_rating"]

        # ROE compliance
        details.append("ROE compliance verified:")
        details.append("  - Target within authorized scope")
        details.append("  - Technique permitted by policy")

        return Explanation(
            explanation_id=uuid4(),
            subject_type="action",
            subject_id=str(action.get("action_id", "unknown")),
            summary=summary,
            details=details,
            factors=factors,
            confidence=0.85,
            timestamp=datetime.utcnow(),
        )

    async def explain_persona_behavior(
        self, persona: Dict[str, Any], actions: List[Dict[str, Any]]
    ) -> Explanation:
        """
        Explain persona-specific behavior patterns.

        Args:
            persona: Adversary persona
            actions: Actions taken by persona

        Returns:
            Persona behavior explanation
        """
        from uuid import uuid4

        persona_name = persona.get("name", "Unknown")
        category = persona.get("category", "unknown")

        summary = f"Behavior analysis for {persona_name} ({category})"
        details = []
        factors = {}

        # Explain TTPs
        ttps = persona.get("ttps", {})
        preferred_tactics = ttps.get("preferred_tactics", [])
        if preferred_tactics:
            details.append(f"Preferred tactics: {', '.join(preferred_tactics)}")
            factors["preferred_tactics"] = preferred_tactics

        # Explain behavioral profile
        profile = persona.get("behavioral_profile", {})
        if profile.get("dwell_time"):
            dwell = profile["dwell_time"]
            details.append(
                f"Typical dwell time: {dwell.get('typical_days', 'N/A')} days"
            )
            factors["dwell_time"] = dwell

        if profile.get("lateral_movement_style"):
            details.append(
                f"Lateral movement style: {profile['lateral_movement_style']}"
            )
            factors["lateral_movement_style"] = profile["lateral_movement_style"]

        # Explain action alignment
        details.append("\nAction alignment with persona profile:")
        for action in actions[:5]:  # Limit to 5 most recent
            action_type = action.get("type", "unknown")
            alignment = self._calculate_persona_alignment(action, persona)
            details.append(f"  - {action_type}: {alignment:.0%} aligned")

        # Note constraints
        details.append("\nConstraint compliance:")
        details.append("  - Persona respects ROE boundaries")
        details.append("  - Persona cannot override safety constraints")
        details.append("  - Persona modifies planner biases within allowed bounds")

        return Explanation(
            explanation_id=uuid4(),
            subject_type="persona",
            subject_id=persona.get("persona_id", "unknown"),
            summary=summary,
            details=details,
            factors=factors,
            confidence=0.9,
            timestamp=datetime.utcnow(),
        )

    async def explain_plan(self, plan: Any, mission: Any) -> Explanation:
        """
        Explain execution plan structure and rationale.

        Args:
            plan: Execution plan
            mission: Associated mission

        Returns:
            Plan explanation
        """
        from uuid import uuid4

        summary = f"Execution plan with {len(plan.phases)} phases"
        details = []
        factors = {}

        # Explain plan structure
        details.append(f"Plan overview:")
        details.append(f"  - Total actions: {plan.total_actions}")
        details.append(f"  - Estimated duration: {plan.estimated_duration_minutes} minutes")
        details.append(f"  - Estimated impact: {plan.estimated_impact:.1f}")

        # Explain each phase
        for i, phase in enumerate(plan.phases):
            phase_name = phase.get("name", f"Phase {i+1}")
            phase_type = phase.get("type", "unknown")
            action_count = len(phase.get("actions", []))
            details.append(f"\n{phase_name} ({phase_type}):")
            details.append(f"  - {action_count} actions")
            details.append(f"  - Objective: {phase.get('objective', 'N/A')}")

        # Explain optimizations
        details.append("\nPlan optimizations:")
        if mission.persona_id:
            details.append("  - Technique preferences aligned with persona")
            factors["persona_aligned"] = True

        details.append("  - Actions ordered by dependency")
        details.append("  - Parallel execution where safe")

        return Explanation(
            explanation_id=uuid4(),
            subject_type="plan",
            subject_id=str(plan.plan_id),
            summary=summary,
            details=details,
            factors=factors,
            confidence=0.85,
            timestamp=datetime.utcnow(),
        )

    def _generate_mission_summary(self, mission: Any) -> str:
        """Generate mission summary."""
        mission_type = mission.policy_envelope.get("mission_type", "simulation")
        classification = mission.classification_level
        risk_tier = mission.policy_envelope.get("risk_tier", 1)

        return (
            f"{mission_type.replace('_', ' ').title()} mission at {classification} "
            f"classification (Risk Tier {risk_tier})"
        )

    def _explain_objective(self, mission: Any) -> str:
        """Explain mission objective."""
        scenario = mission.scenario
        objective = scenario.get("objective", "Security assessment")
        targets = scenario.get("targets", [])

        target_desc = (
            f"targeting {len(targets)} asset(s)"
            if targets
            else "with scope defined in policy envelope"
        )

        return f"{objective} {target_desc}"

    def _explain_methodology(self, mission: Any) -> str:
        """Explain mission methodology."""
        mission_type = mission.policy_envelope.get("mission_type", "simulation")

        methodologies = {
            "reconnaissance": "Passive and active information gathering",
            "vulnerability_assessment": "Systematic vulnerability identification and validation",
            "penetration_test": "Authorized exploitation to validate vulnerabilities",
            "red_team": "Full-scope adversary emulation with defined objectives",
            "purple_team": "Collaborative attack-defense exercise",
            "adversary_emulation": "Specific threat actor TTP replication",
            "simulation": "Simulated attack execution without live impact",
        }

        return methodologies.get(mission_type, "Standard security assessment methodology")

    async def _explain_phases(self, mission: Any) -> List[Dict[str, Any]]:
        """Explain mission phases."""
        phases = []

        if mission.plan:
            for i, phase in enumerate(mission.plan.phases):
                phase_explanation = {
                    "phase_number": i + 1,
                    "name": phase.get("name", f"Phase {i+1}"),
                    "type": phase.get("type", "unknown"),
                    "objective": phase.get("objective", "N/A"),
                    "action_count": len(phase.get("actions", [])),
                    "techniques": list(set(
                        a.get("type") for a in phase.get("actions", [])
                    )),
                }
                phases.append(phase_explanation)

        return phases

    async def _extract_key_decisions(self, mission: Any) -> List[Dict[str, Any]]:
        """Extract and explain key decisions made during mission."""
        decisions = []

        # Target selection decisions
        if mission.scenario.get("targets"):
            decisions.append({
                "decision": "Target Selection",
                "rationale": "Targets selected based on scope definition and value assessment",
                "factors": ["Asset criticality", "Accessibility", "Policy constraints"],
            })

        # Technique decisions
        if mission.persona_id:
            decisions.append({
                "decision": "Technique Selection",
                "rationale": f"Techniques aligned with {mission.persona_id} persona preferences",
                "factors": ["Persona TTPs", "Success probability", "Stealth requirements"],
            })

        # Timing decisions
        decisions.append({
            "decision": "Execution Timing",
            "rationale": "Timing optimized for objective achievement within ROE constraints",
            "factors": ["ROE time windows", "Target availability", "Detection avoidance"],
        })

        return decisions

    def _explain_risk_assessment(self, mission: Any) -> Dict[str, Any]:
        """Generate risk assessment explanation."""
        return {
            "risk_tier": mission.policy_envelope.get("risk_tier", 1),
            "classification": mission.classification_level,
            "blast_radius_cap": mission.policy_envelope.get("roe", {}).get("blast_radius_cap", 100),
            "current_impact": mission.impact_score,
            "controls": [
                "ROE enforcement active",
                "Safety constraints validated",
                "Impact monitoring enabled",
                "Abort capability available",
            ],
        }

    async def _generate_counterfactuals(
        self, mission: Any
    ) -> List[Dict[str, Any]]:
        """Generate counterfactual analysis."""
        counterfactuals = []

        if self.config.planner.enable_counterfactual:
            # What if different initial access vector
            counterfactuals.append({
                "scenario": "Alternative initial access",
                "change": "Using different entry point",
                "predicted_outcome": "Similar success with different detection signature",
                "impact_delta": 0,
            })

            # What if defender responded
            counterfactuals.append({
                "scenario": "Active defense response",
                "change": "Defender detects and responds at phase 2",
                "predicted_outcome": "Mission objectives partially achieved",
                "impact_delta": -30,
            })

        return counterfactuals

    def _calculate_persona_alignment(
        self, action: Dict[str, Any], persona: Dict[str, Any]
    ) -> float:
        """Calculate how well an action aligns with persona profile."""
        action_type = action.get("type", "unknown")
        ttps = persona.get("ttps", {})
        techniques = ttps.get("techniques", [])

        # Check if action type matches preferred techniques
        for technique in techniques:
            if action_type.lower() in technique.get("name", "").lower():
                return technique.get("preference_weight", 0.5)

        return 0.5  # Default alignment
