"""
Frost Gate Spear - Attack Planner

Generates execution plans based on scenarios, personas, and constraints.
Integrates with PersonasManager for persona-aware technique selection.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.mission import ExecutionPlan

if TYPE_CHECKING:
    from ..personas import PersonasManager, AdversaryPersona, PlannerBiases

logger = logging.getLogger(__name__)


@dataclass
class PlanPhase:
    """Single phase in execution plan."""
    phase_id: UUID
    name: str
    phase_type: str
    objective: str
    actions: List[Dict[str, Any]]
    dependencies: List[UUID]
    estimated_duration_minutes: int


class Planner:
    """
    Attack Planner.

    Generates execution plans including:
    - Kill chain phase mapping
    - Technique selection based on persona (via PersonasManager)
    - Multi-branch DAG planning
    - Counterfactual analysis
    - Constraint-aware optimization
    """

    def __init__(self, config: Config, personas_manager: Optional["PersonasManager"] = None):
        """
        Initialize Planner.

        Args:
            config: Application configuration
            personas_manager: Optional PersonasManager for persona integration
        """
        self.config = config
        self._personas_manager = personas_manager
        self._personas: Dict[str, Dict] = {}
        self._technique_db: Dict[str, Dict] = {}
        self._technique_to_tool: Dict[str, List[str]] = {}

    def set_personas_manager(self, personas_manager: "PersonasManager") -> None:
        """
        Set the PersonasManager for persona-aware planning.

        Args:
            personas_manager: PersonasManager instance
        """
        self._personas_manager = personas_manager
        logger.info("PersonasManager connected to Planner")

    async def start(self) -> None:
        """Start Planner."""
        logger.info("Starting Planner...")
        await self._load_technique_database()
        await self._load_technique_tool_mapping()
        logger.info("Planner started")

    async def stop(self) -> None:
        """Stop Planner."""
        logger.info("Stopping Planner...")
        self._personas_manager = None

    async def _load_technique_database(self) -> None:
        """Load MITRE ATT&CK technique database."""
        # In production, load from external source
        self._technique_db = {
            "reconnaissance": ["T1595", "T1592", "T1589"],
            "initial_access": ["T1566", "T1190", "T1133"],
            "execution": ["T1059", "T1204"],
            "persistence": ["T1098", "T1136", "T1053"],
            "privilege_escalation": ["T1068", "T1548"],
            "defense_evasion": ["T1027", "T1070", "T1036"],
            "credential_access": ["T1003", "T1558"],
            "discovery": ["T1087", "T1482", "T1069"],
            "lateral_movement": ["T1021", "T1550"],
            "collection": ["T1114", "T1213"],
            "exfiltration": ["T1041", "T1567"],
            "impact": ["T1486", "T1490"],
        }

    async def _load_technique_tool_mapping(self) -> None:
        """Load mapping of techniques to tools."""
        self._technique_to_tool = {
            # Reconnaissance
            "T1595": ["nmap", "masscan", "shodan"],
            "T1592": ["amass", "subfinder", "dnsrecon"],
            "T1589": ["theharvester", "linkedin_scraper"],
            # Initial Access
            "T1566": ["gophish", "phishing_toolkit"],
            "T1190": ["sqlmap", "nuclei", "metasploit"],
            "T1133": ["vpn_scanner", "rdp_scanner"],
            # Execution
            "T1059": ["powershell", "bash", "python"],
            "T1204": ["macro_builder", "lnk_generator"],
            # Persistence
            "T1098": ["bloodhound", "ad_tools"],
            "T1136": ["net_user", "ldap_tools"],
            "T1053": ["schtasks", "cron_manager"],
            # Privilege Escalation
            "T1068": ["metasploit", "cobalt_strike"],
            "T1548": ["uac_bypass", "sudo_exploit"],
            # Defense Evasion
            "T1027": ["obfuscator", "packer"],
            "T1070": ["log_cleaner", "timestomp"],
            "T1036": ["masquerade_tool"],
            # Credential Access
            "T1003": ["mimikatz", "secretsdump"],
            "T1558": ["rubeus", "kerberoast"],
            # Discovery
            "T1087": ["net_user", "ldapsearch"],
            "T1482": ["bloodhound", "pingcastle"],
            "T1069": ["net_group", "ldapsearch"],
            # Lateral Movement
            "T1021": ["psexec", "ssh_client", "rdp_client"],
            "T1550": ["pth_toolkit", "overpass_the_hash"],
            # Collection
            "T1114": ["mailsniper", "ruler"],
            "T1213": ["sharefinder", "snaffler"],
            # Exfiltration
            "T1041": ["exfil_dns", "exfil_http"],
            "T1567": ["cloud_uploader"],
            # Impact
            "T1486": ["ransomware_sim"],
            "T1490": ["shadow_delete"],
        }

    async def create_plan(self, mission: Any) -> ExecutionPlan:
        """
        Create execution plan for mission.

        Args:
            mission: Mission to plan

        Returns:
            Execution plan
        """
        scenario = mission.scenario
        policy_envelope = mission.policy_envelope
        persona = await self._get_persona(mission.persona_id)

        # Generate phases based on kill chain
        phases = await self._generate_phases(scenario, policy_envelope, persona)

        # Build DAG if multi-branch
        dag = self._build_dag(phases) if len(phases) > 3 else None

        # Calculate estimates
        total_actions = sum(len(p.actions) for p in phases)
        estimated_duration = sum(p.estimated_duration_minutes for p in phases)
        estimated_impact = await self._estimate_plan_impact(phases)

        # Compute plan hash
        plan_hash = self._compute_plan_hash(phases)

        plan = ExecutionPlan(
            plan_id=uuid4(),
            plan_hash=plan_hash,
            created_at=datetime.utcnow(),
            phases=[self._phase_to_dict(p) for p in phases],
            total_actions=total_actions,
            estimated_duration_minutes=estimated_duration,
            estimated_impact=estimated_impact,
            dag=dag,
        )

        logger.info(f"Created plan with {len(phases)} phases, {total_actions} actions")
        return plan

    async def _generate_phases(
        self,
        scenario: Dict[str, Any],
        policy_envelope: Dict[str, Any],
        persona: Optional[Dict[str, Any]],
    ) -> List[PlanPhase]:
        """Generate execution phases."""
        phases = []

        # Get kill chain from scenario or use default
        kill_chain = scenario.get("kill_chain", [
            "reconnaissance",
            "initial_access",
            "execution",
            "persistence",
            "discovery",
            "lateral_movement",
            "collection",
        ])

        # Get constraints
        roe = policy_envelope.get("roe", {})
        max_depth = self.config.planner.max_plan_depth

        previous_phase_id = None

        for i, phase_type in enumerate(kill_chain[:max_depth]):
            # Generate actions for phase
            actions = await self._generate_phase_actions(
                phase_type, scenario, roe, persona
            )

            if not actions:
                continue

            phase = PlanPhase(
                phase_id=uuid4(),
                name=f"{phase_type.replace('_', ' ').title()} Phase",
                phase_type=phase_type,
                objective=self._get_phase_objective(phase_type),
                actions=actions,
                dependencies=[previous_phase_id] if previous_phase_id else [],
                estimated_duration_minutes=len(actions) * 5,
            )

            phases.append(phase)
            previous_phase_id = phase.phase_id

        return phases

    async def _generate_phase_actions(
        self,
        phase_type: str,
        scenario: Dict[str, Any],
        roe: Dict[str, Any],
        persona: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate actions for a phase."""
        actions = []
        targets = scenario.get("targets", [])

        # Get techniques for this phase
        techniques = self._technique_db.get(phase_type, [])

        # Apply persona preferences
        if persona:
            techniques = self._apply_persona_preferences(techniques, persona, phase_type)

        # Filter by ROE
        allowed_tools = roe.get("allowed_tools", [])
        allowed_categories = roe.get("allowed_tool_categories", [])

        for target in targets[:3]:  # Limit targets per phase
            for technique in techniques[:2]:  # Limit techniques
                # Check if technique is allowed
                if not self._technique_allowed(technique, roe, allowed_categories):
                    continue

                action = {
                    "action_id": str(uuid4()),
                    "type": phase_type,
                    "technique_id": technique,
                    "target": {
                        "asset": target.get("name", "unknown"),
                        "type": target.get("type", "unknown"),
                        "network": target.get("network", ""),
                    },
                    "tool": self._select_tool(technique, allowed_tools, persona),
                    "parameters": {},
                    "estimated_duration_minutes": 5,
                }

                actions.append(action)

        return actions

    def _apply_persona_preferences(
        self,
        techniques: List[str],
        persona: Dict[str, Any],
        phase_type: str,
    ) -> List[str]:
        """Apply persona preferences to technique selection."""
        if not persona:
            return techniques

        ttps = persona.get("ttps", {})
        kill_chain_prefs = ttps.get("kill_chain_preferences", {})
        phase_prefs = kill_chain_prefs.get(phase_type, {})
        preferred_techniques = phase_prefs.get("technique_preferences", [])

        if preferred_techniques:
            # Prioritize persona's preferred techniques
            preferred = [t for t in techniques if t in preferred_techniques]
            others = [t for t in techniques if t not in preferred_techniques]
            return preferred + others

        return techniques

    def _technique_allowed(
        self,
        technique: str,
        roe: Dict[str, Any],
        allowed_categories: List[str],
    ) -> bool:
        """Check if technique is allowed by ROE."""
        # Map technique to category (simplified)
        technique_categories = {
            "T1595": "reconnaissance",
            "T1566": "initial_access",
            "T1059": "execution",
            "T1003": "credential_access",
            "T1021": "lateral_movement",
            "T1486": "impact",
        }

        category = technique_categories.get(technique, "unknown")

        # Check if category is allowed
        if allowed_categories and category not in allowed_categories:
            return False

        # Check for explicit disallowed
        disallowed = roe.get("disallowed_techniques", [])
        if technique in disallowed:
            return False

        return True

    def _select_tool(
        self,
        technique: str,
        allowed_tools: List[str],
        persona: Optional[Dict[str, Any]],
    ) -> str:
        """Select tool for technique."""
        # Default tool mapping
        default_tools = {
            "T1595": "nmap",
            "T1566": "phishing_toolkit",
            "T1059": "powershell",
            "T1003": "mimikatz",
            "T1021": "psexec",
        }

        default_tool = default_tools.get(technique, "generic_tool")

        # Check persona preferences
        if persona:
            tool_prefs = persona.get("ttps", {}).get("tool_preferences", [])
            for pref in tool_prefs:
                tool = pref.get("tool", "")
                if tool in allowed_tools or not allowed_tools:
                    return tool

        # Check if default is allowed
        if allowed_tools and default_tool not in allowed_tools:
            return allowed_tools[0] if allowed_tools else "generic_tool"

        return default_tool

    def _get_phase_objective(self, phase_type: str) -> str:
        """Get objective description for phase type."""
        objectives = {
            "reconnaissance": "Gather information about target environment",
            "initial_access": "Establish initial foothold in target network",
            "execution": "Execute malicious code on target systems",
            "persistence": "Maintain access to target environment",
            "privilege_escalation": "Obtain higher-level permissions",
            "defense_evasion": "Avoid detection by security controls",
            "credential_access": "Obtain account credentials",
            "discovery": "Learn about target environment",
            "lateral_movement": "Move through target network",
            "collection": "Gather data of interest",
            "exfiltration": "Extract data from target",
            "impact": "Manipulate, interrupt, or destroy systems",
        }
        return objectives.get(phase_type, "Execute phase actions")

    def _build_dag(self, phases: List[PlanPhase]) -> Dict[str, Any]:
        """Build DAG representation of plan."""
        nodes = []
        edges = []

        for phase in phases:
            nodes.append({
                "id": str(phase.phase_id),
                "name": phase.name,
                "type": phase.phase_type,
            })

            for dep in phase.dependencies:
                edges.append({
                    "from": str(dep),
                    "to": str(phase.phase_id),
                })

        return {
            "nodes": nodes,
            "edges": edges,
        }

    async def _estimate_plan_impact(self, phases: List[PlanPhase]) -> float:
        """Estimate overall plan impact."""
        total_impact = 0.0

        phase_weights = {
            "reconnaissance": 0.1,
            "initial_access": 0.3,
            "execution": 0.4,
            "persistence": 0.5,
            "privilege_escalation": 0.6,
            "credential_access": 0.5,
            "lateral_movement": 0.6,
            "collection": 0.4,
            "exfiltration": 0.7,
            "impact": 1.0,
        }

        for phase in phases:
            weight = phase_weights.get(phase.phase_type, 0.3)
            phase_impact = len(phase.actions) * weight * 5  # Base impact per action
            total_impact += phase_impact

        return min(total_impact, 100)  # Cap at 100

    def _compute_plan_hash(self, phases: List[PlanPhase]) -> str:
        """Compute hash of plan."""
        plan_data = [self._phase_to_dict(p) for p in phases]
        plan_str = json.dumps(plan_data, sort_keys=True)
        return f"sha256:{hashlib.sha256(plan_str.encode()).hexdigest()}"

    def _phase_to_dict(self, phase: PlanPhase) -> Dict[str, Any]:
        """Convert phase to dictionary."""
        return {
            "phase_id": str(phase.phase_id),
            "name": phase.name,
            "type": phase.phase_type,
            "objective": phase.objective,
            "actions": phase.actions,
            "dependencies": [str(d) for d in phase.dependencies],
            "estimated_duration_minutes": phase.estimated_duration_minutes,
        }

    async def _get_persona(self, persona_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Load persona configuration via PersonasManager.

        Args:
            persona_id: Persona identifier

        Returns:
            Persona data dictionary or None
        """
        if not persona_id:
            return None

        # Check local cache first
        if persona_id in self._personas:
            return self._personas[persona_id]

        # Use PersonasManager if available
        if self._personas_manager:
            try:
                persona = self._personas_manager.get_persona(persona_id)
                if persona:
                    # Convert to dict and cache
                    persona_dict = persona.to_dict()
                    self._personas[persona_id] = persona_dict
                    logger.debug(f"Loaded persona {persona.name} from PersonasManager")
                    return persona_dict
            except Exception as e:
                logger.warning(f"Failed to load persona {persona_id}: {e}")

        return None

    async def get_persona_biases(self, persona_id: str) -> Optional["PlannerBiases"]:
        """
        Get planner biases for persona from PersonasManager.

        Args:
            persona_id: Persona identifier

        Returns:
            PlannerBiases or None
        """
        if not self._personas_manager:
            return None

        return self._personas_manager.get_planner_biases(persona_id)

    async def get_persona_techniques(self, persona_id: str) -> List[Dict[str, Any]]:
        """
        Get technique preferences for persona from PersonasManager.

        Args:
            persona_id: Persona identifier

        Returns:
            List of technique preferences
        """
        if not self._personas_manager:
            return []

        prefs = self._personas_manager.get_technique_preferences(persona_id)
        return [p.to_dict() if hasattr(p, 'to_dict') else p for p in prefs]

    async def generate_counterfactuals(
        self, plan: ExecutionPlan, mission: Any
    ) -> List[Dict[str, Any]]:
        """
        Generate counterfactual alternative plans.

        Args:
            plan: Original plan
            mission: Mission context

        Returns:
            List of counterfactual scenarios
        """
        if not self.config.planner.enable_counterfactual:
            return []

        counterfactuals = []

        # Alternative initial access
        counterfactuals.append({
            "scenario": "Alternative initial access vector",
            "change": "Using different entry technique",
            "phases_affected": ["initial_access"],
            "impact_delta": 0,
        })

        # Faster execution path
        counterfactuals.append({
            "scenario": "Aggressive execution path",
            "change": "Skip stealth phases, direct exploitation",
            "phases_affected": ["defense_evasion", "discovery"],
            "impact_delta": 20,
        })

        # Stealth optimized
        counterfactuals.append({
            "scenario": "Stealth optimized",
            "change": "Extended dwell time, minimal footprint",
            "phases_affected": ["all"],
            "impact_delta": -15,
        })

        return counterfactuals
