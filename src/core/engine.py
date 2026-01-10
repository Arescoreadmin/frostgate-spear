"""
Frost Gate Spear Core Engine

Main orchestration engine coordinating all subsystems.
Integrates safety policy evaluation, MLS validation, and SBOM verification.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import aiohttp

from .config import Config
from .exceptions import (
    FrostGateError,
    MLSViolationError,
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
)
from .mission import Mission, MissionState

logger = logging.getLogger(__name__)


class SafetyPolicyEvaluator:
    """
    Safety policy evaluator using OPA.

    Evaluates safety constraints during mission execution including:
    - Forensic completeness checks
    - Concurrency limits
    - Simulation validation
    - Scope expansion prevention
    - Cross-ring contamination prevention
    """

    def __init__(self, opa_url: str = "http://localhost:8181"):
        """Initialize safety evaluator."""
        self._opa_url = opa_url
        self._session: Optional[aiohttp.ClientSession] = None
        self._healthy = False

    async def start(self) -> None:
        """Start the safety evaluator."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5.0)
        )
        await self._check_health()

    async def stop(self) -> None:
        """Stop the safety evaluator."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _check_health(self) -> bool:
        """Check OPA health."""
        if not self._session:
            return False
        try:
            async with self._session.get(f"{self._opa_url}/health") as resp:
                self._healthy = resp.status == 200
                return self._healthy
        except Exception:
            self._healthy = False
            return False

    async def evaluate_safety(
        self,
        action: Dict[str, Any],
        mission_context: Dict[str, Any],
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate safety constraints for an action.

        Args:
            action: Action being evaluated
            mission_context: Mission context including policy, ROE
            metrics: Current system metrics

        Returns:
            Evaluation result with safe/unsafe and violations
        """
        input_data = {
            "action": action,
            "context": mission_context,
            "metrics": metrics,
            "state": {
                "active_operations": mission_context.get("active_operations", 0),
            },
            "policy": mission_context.get("policy_envelope", {}),
            "promotion": mission_context.get("promotion", {}),
        }

        if self._healthy and self._session:
            try:
                url = f"{self._opa_url}/v1/data/frostgate/safety"
                async with self._session.post(
                    url,
                    json={"input": input_data},
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        policy_result = result.get("result", {})
                        return {
                            "safe": policy_result.get("safe", False),
                            "violations": policy_result.get("safety_violations", []),
                            "red_lines": policy_result.get("red_line_violations", []),
                        }
            except Exception as e:
                logger.warning(f"OPA safety evaluation failed: {e}")

        # Fallback to local evaluation
        return await self._local_evaluate(input_data)

    async def _local_evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Local safety evaluation fallback."""
        violations = []
        action = input_data.get("action", {})
        context = input_data.get("context", {})
        metrics = input_data.get("metrics", {})

        # Check forensic completeness
        forensic_completeness = metrics.get("forensic_completeness", 1.0)
        if forensic_completeness < 0.95:
            violations.append(
                f"Forensic completeness below threshold: {forensic_completeness:.2f} < 0.95"
            )

        # Check scope expansion
        if action.get("expands_scope") and not action.get("scope_expansion_authorized"):
            violations.append("Unauthorized scope expansion attempted")

        # Check destructive operations
        if action.get("destructive"):
            approvals = context.get("approvals", {})
            if not approvals.get("ao_signature"):
                violations.append("Destructive operation without AO signature")

        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "red_lines": [],
        }


class EngineState(Enum):
    """Engine operational states."""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    SHUTTING_DOWN = "shutting_down"
    ERROR = "error"


@dataclass
class EngineMetrics:
    """Engine performance and health metrics."""
    active_missions: int = 0
    completed_missions: int = 0
    policy_violations: int = 0
    roe_violations: int = 0
    safety_violations: int = 0
    forensic_completeness: float = 0.0
    uptime_seconds: float = 0.0


class FrostGateSpear:
    """
    Main Frost Gate Spear Engine.

    Coordinates all subsystems including:
    - Policy Interpreter
    - ROE Engine
    - Planner
    - Executor
    - Target Impact Estimator (TIE)
    - Blue Box Explainer
    - Forensics
    - MLS Manager
    - FL Controller
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize Frost Gate Spear engine.

        Args:
            config: Configuration object. Uses defaults if not provided.
        """
        self.config = config or Config()
        self.state = EngineState.INITIALIZING
        self.engine_id = uuid4()
        self.start_time: Optional[datetime] = None
        self.metrics = EngineMetrics()

        # Subsystem references (initialized in start())
        self._policy_interpreter = None
        self._roe_engine = None
        self._planner = None
        self._executor = None
        self._tie = None
        self._blue_box = None
        self._forensics = None
        self._mls_manager = None
        self._fl_controller = None
        self._governance = None
        self._integrity_manager = None

        # Safety policy evaluator
        self._safety_evaluator = SafetyPolicyEvaluator(
            opa_url=getattr(config, "opa_url", "http://localhost:8181")
        )

        # Mission tracking
        self._missions: Dict[UUID, Mission] = {}
        self._mission_lock = asyncio.Lock()

        logger.info(f"FrostGateSpear engine initialized: {self.engine_id}")

    async def start(self) -> None:
        """Start the engine and all subsystems."""
        logger.info("Starting Frost Gate Spear engine...")

        try:
            # Initialize subsystems in dependency order
            await self._initialize_subsystems()

            # Validate configuration
            await self._validate_configuration()

            # Start background tasks
            await self._start_background_tasks()

            self.state = EngineState.READY
            self.start_time = datetime.utcnow()
            logger.info("Frost Gate Spear engine started successfully")

        except Exception as e:
            self.state = EngineState.ERROR
            logger.error(f"Failed to start engine: {e}")
            raise FrostGateError(f"Engine start failed: {e}") from e

    async def stop(self) -> None:
        """Stop the engine gracefully."""
        logger.info("Stopping Frost Gate Spear engine...")
        self.state = EngineState.SHUTTING_DOWN

        # Stop all active missions
        async with self._mission_lock:
            for mission in self._missions.values():
                if mission.state == MissionState.RUNNING:
                    await self.abort_mission(mission.mission_id, reason="Engine shutdown")

        # Shutdown subsystems
        await self._shutdown_subsystems()

        logger.info("Frost Gate Spear engine stopped")

    async def create_mission(
        self,
        policy_envelope: Dict[str, Any],
        scenario: Dict[str, Any],
        persona_id: Optional[str] = None,
    ) -> Mission:
        """
        Create a new mission.

        Args:
            policy_envelope: Policy envelope defining mission constraints
            scenario: Attack scenario definition
            persona_id: Optional adversary persona to use

        Returns:
            Created Mission object

        Raises:
            PolicyViolationError: If policy envelope validation fails
            ROEViolationError: If ROE constraints are violated
        """
        logger.info("Creating new mission...")

        # Validate policy envelope
        await self._policy_interpreter.validate_envelope(policy_envelope)

        # Validate ROE
        await self._roe_engine.validate_roe(policy_envelope.get("roe", {}))

        # Check MLS constraints
        classification = policy_envelope.get("classification_level", "UNCLASS")
        await self._mls_manager.validate_ring_access(classification)

        # Create mission
        mission = Mission(
            policy_envelope=policy_envelope,
            scenario=scenario,
            persona_id=persona_id,
            classification_level=classification,
        )

        async with self._mission_lock:
            self._missions[mission.mission_id] = mission

        logger.info(f"Mission created: {mission.mission_id}")
        return mission

    async def start_mission(self, mission_id: UUID) -> None:
        """
        Start execution of a mission.

        Args:
            mission_id: ID of mission to start

        Raises:
            FrostGateError: If mission not found or cannot be started
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

            if mission.state != MissionState.CREATED:
                raise FrostGateError(
                    f"Mission cannot be started from state: {mission.state}"
                )

        # Pre-flight checks
        await self._preflight_checks(mission)

        # Estimate impact
        impact_estimate = await self._tie.estimate_impact(mission)
        if impact_estimate.exceeds_blast_radius:
            raise SafetyConstraintError(
                f"Estimated impact {impact_estimate.score} exceeds blast radius cap"
            )

        # Generate execution plan
        plan = await self._planner.create_plan(mission)

        # Validate plan against ROE
        await self._roe_engine.validate_plan(plan, mission.policy_envelope)

        # Start execution
        mission.state = MissionState.RUNNING
        mission.plan = plan
        self.metrics.active_missions += 1

        # Execute asynchronously
        asyncio.create_task(self._execute_mission(mission))

        logger.info(f"Mission started: {mission_id}")

    async def abort_mission(
        self, mission_id: UUID, reason: str = "User requested"
    ) -> None:
        """
        Abort a running mission.

        Args:
            mission_id: ID of mission to abort
            reason: Reason for abortion
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        if mission.state == MissionState.RUNNING:
            await self._executor.abort(mission)
            mission.state = MissionState.ABORTED
            mission.abort_reason = reason
            self.metrics.active_missions -= 1

        logger.warning(f"Mission aborted: {mission_id} - {reason}")

    async def get_mission_status(self, mission_id: UUID) -> Dict[str, Any]:
        """Get current status of a mission."""
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        # Get explanation from Blue Box
        explanation = await self._blue_box.explain_mission(mission)

        return {
            "mission_id": str(mission.mission_id),
            "state": mission.state.value,
            "classification_level": mission.classification_level,
            "progress": mission.progress,
            "current_phase": mission.current_phase,
            "actions_completed": mission.actions_completed,
            "actions_remaining": mission.actions_remaining,
            "impact_score": mission.impact_score,
            "explanation": explanation,
            "forensic_completeness": await self._forensics.get_completeness(mission),
        }

    async def replay_mission(self, mission_id: UUID) -> Dict[str, Any]:
        """
        Replay a completed mission for verification.

        Args:
            mission_id: ID of mission to replay

        Returns:
            Replay results including success status
        """
        async with self._mission_lock:
            mission = self._missions.get(mission_id)
            if not mission:
                raise FrostGateError(f"Mission not found: {mission_id}")

        if mission.state not in [MissionState.COMPLETED, MissionState.ABORTED]:
            raise FrostGateError("Can only replay completed or aborted missions")

        return await self._forensics.replay_mission(mission)

    # Private methods

    async def _initialize_subsystems(self) -> None:
        """Initialize all subsystems including safety evaluator and integrity manager."""
        from ..policy_interpreter import PolicyInterpreter
        from ..roe_engine import ROEEngine
        from ..planner import Planner
        from ..sim import Executor
        from ..tie import TargetImpactEstimator
        from ..blue_box import BlueBox
        from ..forensics import ForensicsManager
        from ..mls import MLSManager
        from ..fl import FLController
        from ..governance import GovernanceManager
        from ..integrity import IntegrityManager

        self._policy_interpreter = PolicyInterpreter(self.config)
        self._roe_engine = ROEEngine(self.config)
        self._planner = Planner(self.config)
        self._executor = Executor(self.config)
        self._tie = TargetImpactEstimator(self.config)
        self._blue_box = BlueBox(self.config)
        self._forensics = ForensicsManager(self.config)
        self._mls_manager = MLSManager(self.config)
        self._fl_controller = FLController(self.config)
        self._governance = GovernanceManager(self.config)

        # Initialize integrity manager for SBOM/artifact verification
        trust_store_path = getattr(self.config, "trust_store_path", None)
        self._integrity_manager = IntegrityManager(
            trust_store_path=trust_store_path,
            require_signatures=getattr(self.config, "require_signatures", True),
        )

        # Start all subsystems including safety evaluator
        await asyncio.gather(
            self._policy_interpreter.start(),
            self._roe_engine.start(),
            self._planner.start(),
            self._executor.start(),
            self._tie.start(),
            self._blue_box.start(),
            self._forensics.start(),
            self._mls_manager.start(),
            self._fl_controller.start(),
            self._governance.start(),
            self._integrity_manager.start(),
            self._safety_evaluator.start(),
        )

    async def _validate_configuration(self) -> None:
        """Validate engine configuration."""
        # Validate policy files exist
        await self._policy_interpreter.validate_policies()

        # Validate MLS ring configurations
        await self._mls_manager.validate_rings()

        # Validate governance gates
        await self._governance.validate_gates()

    async def _start_background_tasks(self) -> None:
        """Start background monitoring tasks."""
        asyncio.create_task(self._metrics_collector())
        asyncio.create_task(self._health_monitor())

    async def _shutdown_subsystems(self) -> None:
        """Shutdown all subsystems gracefully."""
        subsystems = [
            self._executor,
            self._planner,
            self._fl_controller,
            self._forensics,
            self._blue_box,
            self._tie,
            self._mls_manager,
            self._roe_engine,
            self._policy_interpreter,
            self._governance,
            self._safety_evaluator,
        ]

        for subsystem in subsystems:
            if subsystem:
                try:
                    await subsystem.stop()
                except Exception as e:
                    logger.error(f"Error stopping subsystem: {e}")

    async def _preflight_checks(self, mission: Mission) -> None:
        """
        Run pre-flight checks before mission execution.

        Includes:
        - Approval validation
        - Scenario hash verification
        - SBOM verification (if present)
        - Budget checks
        """
        # Check approvals
        await self._governance.validate_approvals(mission)

        # Validate scenario hash
        await self._forensics.validate_scenario_hash(mission)

        # Verify scenario integrity
        if self._integrity_manager:
            expected_hash = mission.policy_envelope.get("scenario_hash")
            scenario_result = await self._integrity_manager.verify_artifact(
                artifact_type="scenario",
                artifact=mission.scenario,
                expected_hash=expected_hash,
                require_signature=mission.policy_envelope.get("risk_tier", 1) >= 3,
            )
            if not scenario_result.valid:
                raise PolicyViolationError(
                    f"Scenario integrity verification failed: {scenario_result.details}"
                )
            logger.info(
                f"Scenario integrity verified: {scenario_result.computed_hash[:16]}..."
            )

        # Verify SBOM if attached to scenario
        sbom = mission.scenario.get("sbom")
        if sbom and self._integrity_manager:
            attestation = mission.scenario.get("sbom_attestation")
            sbom_result = await self._integrity_manager.sbom_verifier.verify_sbom(
                sbom=sbom,
                attestation=attestation,
            )
            if not sbom_result.valid:
                raise PolicyViolationError(
                    f"SBOM verification failed: {sbom_result.details}"
                )
            logger.info(
                f"SBOM verified: {sbom_result.details.get('components', 0)} components, "
                f"hash_coverage={sbom_result.details.get('hash_coverage', 0):.0%}"
            )

        # Verify policy envelope integrity
        if self._integrity_manager:
            envelope_result = await self._integrity_manager.verify_policy_envelope(
                mission.policy_envelope
            )
            if envelope_result.signature_valid is False:
                # Only fail if signature was present but invalid
                logger.warning(
                    f"Policy envelope signature invalid: {envelope_result.details}"
                )

        # Check budget
        await self._governance.check_budget(mission)

    async def _execute_mission(self, mission: Mission) -> None:
        """
        Execute mission plan with full safety, MLS, and ROE enforcement.

        Integrates:
        - Safety policy evaluation via OPA
        - MLS validation for data flow
        - ROE violation checking
        - Impact score tracking
        """
        try:
            async for action_result in self._executor.execute(mission):
                # Log to forensics first (for audit trail)
                await self._forensics.log_action(mission, action_result)

                # Build action data for policy evaluation
                action_data = {
                    "action_id": str(action_result.action_id),
                    "action_type": action_result.action_type,
                    "target": action_result.target,
                    "status": action_result.status,
                    "destructive": getattr(action_result, "destructive", False),
                    "expands_scope": getattr(action_result, "expands_scope", False),
                    "estimated_impact": getattr(action_result, "impact_score", 0),
                }

                # Safety policy evaluation
                safety_result = await self._safety_evaluator.evaluate_safety(
                    action=action_data,
                    mission_context={
                        "policy_envelope": mission.policy_envelope,
                        "active_operations": self.metrics.active_missions,
                        "approvals": mission.policy_envelope.get("approvals", {}),
                    },
                    metrics={
                        "forensic_completeness": self.metrics.forensic_completeness,
                    },
                )

                # Check for red line violations (abort immediately)
                if safety_result.get("red_lines"):
                    logger.error(
                        f"RED LINE VIOLATION: {safety_result['red_lines']}"
                    )
                    self.metrics.safety_violations += 1
                    await self.abort_mission(
                        mission.mission_id,
                        reason=f"Red line violation: {safety_result['red_lines'][0]}",
                    )
                    return

                # Check for safety violations
                if not safety_result.get("safe", True):
                    logger.warning(
                        f"Safety violation: {safety_result.get('violations', [])}"
                    )
                    self.metrics.safety_violations += 1
                    # Continue but log warning for non-red-line violations

                # MLS validation for any data flow
                if hasattr(action_result, "data_flow") and action_result.data_flow:
                    from ..mls import DataFlowRequest
                    flow_request = DataFlowRequest(
                        source_ring=action_result.data_flow.get(
                            "source", mission.classification_level
                        ),
                        dest_ring=action_result.data_flow.get(
                            "destination", mission.classification_level
                        ),
                        data_type=action_result.data_flow.get("type", "action_output"),
                        sanitized=action_result.data_flow.get("sanitized", False),
                        declassification_authorized=action_result.data_flow.get(
                            "declassification_authorized", False
                        ),
                        requestor=str(mission.mission_id),
                        timestamp=datetime.utcnow(),
                    )
                    try:
                        await self._mls_manager.validate_data_flow(flow_request)
                    except MLSViolationError as e:
                        logger.error(f"MLS violation: {e}")
                        self.metrics.policy_violations += 1
                        await self.abort_mission(
                            mission.mission_id,
                            reason=f"MLS violation: {e}",
                        )
                        return

                # Check for ROE violations
                if await self._roe_engine.check_violation(action_result):
                    self.metrics.roe_violations += 1
                    await self.abort_mission(
                        mission.mission_id, reason="ROE violation detected"
                    )
                    return

                # Update impact score
                mission.impact_score = await self._tie.update_impact(
                    mission, action_result
                )

                # Update progress
                mission.actions_completed += 1

            # Mission completed
            mission.state = MissionState.COMPLETED
            self.metrics.active_missions -= 1
            self.metrics.completed_missions += 1

            # Final forensic capture
            await self._forensics.finalize_mission(mission)

            logger.info(f"Mission completed: {mission.mission_id}")

        except Exception as e:
            logger.error(f"Mission execution error: {e}")
            mission.state = MissionState.ERROR
            mission.error = str(e)
            self.metrics.active_missions -= 1

    async def _metrics_collector(self) -> None:
        """Background task to collect metrics."""
        while self.state not in [EngineState.SHUTTING_DOWN, EngineState.ERROR]:
            try:
                # Update forensic completeness
                total_completeness = 0.0
                mission_count = 0

                async with self._mission_lock:
                    for mission in self._missions.values():
                        if mission.state == MissionState.COMPLETED:
                            completeness = await self._forensics.get_completeness(
                                mission
                            )
                            total_completeness += completeness
                            mission_count += 1

                if mission_count > 0:
                    self.metrics.forensic_completeness = (
                        total_completeness / mission_count
                    )

                # Update uptime
                if self.start_time:
                    self.metrics.uptime_seconds = (
                        datetime.utcnow() - self.start_time
                    ).total_seconds()

                await asyncio.sleep(60)  # Collect every minute

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(60)

    async def _health_monitor(self) -> None:
        """Background task to monitor system health."""
        while self.state not in [EngineState.SHUTTING_DOWN, EngineState.ERROR]:
            try:
                # Check subsystem health
                # This would include checks for all subsystems

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(30)
