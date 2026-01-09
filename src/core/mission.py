"""
Frost Gate Spear Mission Definition

Mission state management and lifecycle.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4


class MissionState(Enum):
    """Mission lifecycle states."""
    CREATED = "created"
    VALIDATED = "validated"
    APPROVED = "approved"
    PLANNING = "planning"
    PLANNED = "planned"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"
    ERROR = "error"


class MissionType(Enum):
    """Types of missions."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TEST = "penetration_test"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    ADVERSARY_EMULATION = "adversary_emulation"
    TRAINING = "training"
    SIMULATION = "simulation"


@dataclass
class MissionApproval:
    """Mission approval record."""
    approver_id: str
    approver_name: str
    role: str
    timestamp: datetime
    signature: str
    scope_hash: str
    valid: bool = True
    expiry: Optional[datetime] = None


@dataclass
class ActionResult:
    """Result of an executed action."""
    action_id: UUID
    action_type: str
    target: str
    status: str
    timestamp: datetime
    duration_ms: int
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    impact_score: float = 0.0
    alerts_generated: int = 0
    artifacts: List[str] = field(default_factory=list)


@dataclass
class ExecutionPlan:
    """Mission execution plan."""
    plan_id: UUID
    plan_hash: str
    created_at: datetime
    phases: List[Dict[str, Any]]
    total_actions: int
    estimated_duration_minutes: int
    estimated_impact: float
    dag: Optional[Dict[str, Any]] = None  # DAG representation for multi-branch


@dataclass
class Mission:
    """
    Mission definition and state.

    Represents a complete mission from creation through completion.
    """
    # Identity
    mission_id: UUID = field(default_factory=uuid4)

    # Policy and constraints
    policy_envelope: Dict[str, Any] = field(default_factory=dict)
    scenario: Dict[str, Any] = field(default_factory=dict)
    persona_id: Optional[str] = None
    classification_level: str = "UNCLASS"

    # State
    state: MissionState = MissionState.CREATED
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Plan
    plan: Optional[ExecutionPlan] = None

    # Progress
    progress: float = 0.0
    current_phase: str = ""
    actions_completed: int = 0
    actions_remaining: int = 0

    # Impact
    impact_score: float = 0.0
    alerts_generated: int = 0

    # Results
    action_results: List[ActionResult] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # Approvals
    approvals: List[MissionApproval] = field(default_factory=list)

    # Error handling
    error: Optional[str] = None
    abort_reason: Optional[str] = None

    # Forensic hashes
    scenario_hash: str = ""
    plan_hash: str = ""
    lineage_hash: str = ""

    def __post_init__(self):
        """Initialize computed fields."""
        if self.policy_envelope:
            self._extract_constraints()

    def _extract_constraints(self):
        """Extract key constraints from policy envelope."""
        self.mission_type = self.policy_envelope.get("mission_type", "simulation")
        self.risk_tier = self.policy_envelope.get("risk_tier", 1)
        self.scope_id = self.policy_envelope.get("scope_id", "")

        roe = self.policy_envelope.get("roe", {})
        self.blast_radius_cap = roe.get("blast_radius_cap", 100.0)
        self.alert_footprint_cap = roe.get("alert_footprint_cap")

        budget = self.policy_envelope.get("budget_cap", {})
        self.budget_cap_usd = budget.get("cost_usd", float("inf"))

    def add_approval(self, approval: MissionApproval) -> None:
        """Add an approval to the mission."""
        self.approvals.append(approval)

    def has_required_approvals(self, required_roles: List[str]) -> bool:
        """Check if all required approvals are present."""
        approved_roles = {
            a.role for a in self.approvals if a.valid and (
                a.expiry is None or a.expiry > datetime.utcnow()
            )
        }
        return all(role in approved_roles for role in required_roles)

    def add_action_result(self, result: ActionResult) -> None:
        """Record an action result."""
        self.action_results.append(result)
        self.actions_completed += 1

        if self.plan:
            self.progress = self.actions_completed / self.plan.total_actions
            self.actions_remaining = (
                self.plan.total_actions - self.actions_completed
            )

        self.impact_score += result.impact_score
        self.alerts_generated += result.alerts_generated

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a security finding."""
        self.findings.append({
            **finding,
            "timestamp": datetime.utcnow().isoformat(),
            "mission_id": str(self.mission_id),
        })

    def to_dict(self) -> Dict[str, Any]:
        """Convert mission to dictionary representation."""
        return {
            "mission_id": str(self.mission_id),
            "state": self.state.value,
            "classification_level": self.classification_level,
            "mission_type": getattr(self, "mission_type", "simulation"),
            "risk_tier": getattr(self, "risk_tier", 1),
            "persona_id": self.persona_id,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "actions_completed": self.actions_completed,
            "actions_remaining": self.actions_remaining,
            "impact_score": self.impact_score,
            "alerts_generated": self.alerts_generated,
            "findings_count": len(self.findings),
            "error": self.error,
            "abort_reason": self.abort_reason,
            "scenario_hash": self.scenario_hash,
            "plan_hash": self.plan_hash,
        }

    def get_forensic_record(self) -> Dict[str, Any]:
        """Get complete forensic record for the mission."""
        return {
            "mission": self.to_dict(),
            "policy_envelope": self.policy_envelope,
            "scenario": self.scenario,
            "plan": {
                "plan_id": str(self.plan.plan_id) if self.plan else None,
                "plan_hash": self.plan.plan_hash if self.plan else None,
                "phases": self.plan.phases if self.plan else [],
            },
            "action_results": [
                {
                    "action_id": str(r.action_id),
                    "action_type": r.action_type,
                    "target": r.target,
                    "status": r.status,
                    "timestamp": r.timestamp.isoformat(),
                    "duration_ms": r.duration_ms,
                    "impact_score": r.impact_score,
                    "error": r.error,
                }
                for r in self.action_results
            ],
            "findings": self.findings,
            "approvals": [
                {
                    "approver_id": a.approver_id,
                    "role": a.role,
                    "timestamp": a.timestamp.isoformat(),
                    "scope_hash": a.scope_hash,
                }
                for a in self.approvals
            ],
            "hashes": {
                "scenario": self.scenario_hash,
                "plan": self.plan_hash,
                "lineage": self.lineage_hash,
            },
        }
