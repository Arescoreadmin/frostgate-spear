"""
Frost Gate Spear Core Engine

Main orchestration engine coordinating all subsystems.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from .config import Config
from .exceptions import (
    FrostGateError,
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
)
from .mission import Mission, MissionState

logger = logging.getLogger(__name__)


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
        """Initialize all subsystems."""
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

        # Start all subsystems
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
        ]

        for subsystem in subsystems:
            if subsystem:
                try:
                    await subsystem.stop()
                except Exception as e:
                    logger.error(f"Error stopping subsystem: {e}")

    async def _preflight_checks(self, mission: Mission) -> None:
        """Run pre-flight checks before mission execution."""
        # Check approvals
        await self._governance.validate_approvals(mission)

        # Validate scenario hash
        await self._forensics.validate_scenario_hash(mission)

        # Check budget
        await self._governance.check_budget(mission)

    async def _execute_mission(self, mission: Mission) -> None:
        """Execute mission plan."""
        try:
            async for action_result in self._executor.execute(mission):
                # Log to forensics
                await self._forensics.log_action(mission, action_result)

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
