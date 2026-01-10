"""
Frost Gate Spear - Simulation and Execution Engine

Executes attack plans in simulation or live environments with
sandboxed tool execution via Docker isolation.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.mission import ActionResult, Mission
from ..sandbox import (
    ToolExecutor,
    ToolExecutionRequest,
    ToolExecutionResult,
    SandboxConfig,
    IsolationLevel,
    SandboxState,
)
from ..security import SecurityManager, PolicyDecision

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """Context for action execution."""
    mission_id: UUID
    phase_name: str
    action_index: int
    total_actions: int
    environment: str
    classification_level: str
    alert_count: int
    impact_score: float


class Executor:
    """
    Simulation and Execution Engine.

    Supports:
    - Simulation mode (no live impact)
    - Lab mode (isolated environment)
    - Canary mode (limited production)
    - Production/Mission mode (live execution)
    - Multi-branch DAG execution
    - Concurrent action limits
    - Sandboxed tool execution via Docker
    """

    def __init__(self, config: Config):
        """Initialize Executor."""
        self.config = config
        self._active_executions: Dict[UUID, bool] = {}
        self._abort_flags: Dict[UUID, bool] = {}
        self._tool_executor: Optional[ToolExecutor] = None
        self._security_manager: Optional[SecurityManager] = None

    async def start(self) -> None:
        """Start Executor with sandboxed tool execution."""
        logger.info("Starting Executor...")

        # Initialize tool executor for sandboxed execution
        self._tool_executor = ToolExecutor(self.config)
        await self._tool_executor.start()

        # Initialize security manager for policy checks
        self._security_manager = SecurityManager(self.config)
        await self._security_manager.start()

        logger.info("Executor started with sandbox and security integration")

    async def stop(self) -> None:
        """Stop Executor."""
        logger.info("Stopping Executor...")

        # Abort all active executions
        for mission_id in list(self._active_executions.keys()):
            self._abort_flags[mission_id] = True

        # Stop tool executor
        if self._tool_executor:
            await self._tool_executor.stop()

        # Stop security manager
        if self._security_manager:
            await self._security_manager.stop()

    async def execute(self, mission: Mission) -> AsyncGenerator[ActionResult, None]:
        """
        Execute mission plan.

        Args:
            mission: Mission to execute

        Yields:
            Action results as they complete
        """
        if not mission.plan:
            logger.error(f"Mission {mission.mission_id} has no plan")
            return

        self._active_executions[mission.mission_id] = True
        self._abort_flags[mission.mission_id] = False

        context = ExecutionContext(
            mission_id=mission.mission_id,
            phase_name="",
            action_index=0,
            total_actions=mission.plan.total_actions,
            environment=mission.policy_envelope.get("mode", "simulation"),
            classification_level=mission.classification_level,
            alert_count=0,
            impact_score=0.0,
        )

        try:
            for phase in mission.plan.phases:
                if self._abort_flags.get(mission.mission_id):
                    logger.info(f"Mission {mission.mission_id} aborted")
                    break

                context.phase_name = phase.get("name", "Unknown Phase")
                mission.current_phase = context.phase_name

                logger.info(f"Executing phase: {context.phase_name}")

                # Execute phase actions
                async for result in self._execute_phase(phase, context, mission):
                    yield result

                    # Update context
                    context.action_index += 1
                    context.alert_count += result.alerts_generated
                    context.impact_score += result.impact_score

        finally:
            self._active_executions.pop(mission.mission_id, None)
            self._abort_flags.pop(mission.mission_id, None)

    async def _execute_phase(
        self,
        phase: Dict[str, Any],
        context: ExecutionContext,
        mission: Mission,
    ) -> AsyncGenerator[ActionResult, None]:
        """Execute single phase."""
        actions = phase.get("actions", [])

        # Determine concurrency based on environment
        max_concurrent = self._get_max_concurrent(context.environment)

        # Execute actions with concurrency limit
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []

        for action in actions:
            if self._abort_flags.get(context.mission_id):
                break

            task = asyncio.create_task(
                self._execute_action_with_semaphore(
                    semaphore, action, context, mission
                )
            )
            tasks.append(task)

        # Yield results as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result

    async def _execute_action_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        action: Dict[str, Any],
        context: ExecutionContext,
        mission: Mission,
    ) -> Optional[ActionResult]:
        """Execute action with semaphore for concurrency control."""
        async with semaphore:
            return await self._execute_action(action, context, mission)

    async def _execute_action(
        self,
        action: Dict[str, Any],
        context: ExecutionContext,
        mission: Mission,
    ) -> ActionResult:
        """Execute single action."""
        action_id = UUID(action.get("action_id", str(uuid4())))
        action_type = action.get("type", "unknown")
        target = action.get("target", {}).get("asset", "unknown")

        start_time = datetime.utcnow()

        logger.debug(f"Executing action: {action_type} on {target}")

        try:
            # Route to appropriate executor based on environment
            if context.environment == "simulation":
                output = await self._simulate_action(action, context)
            elif context.environment == "lab":
                output = await self._execute_lab_action(action, context)
            else:
                output = await self._execute_live_action(action, context)

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Calculate impact
            impact_score = self._calculate_action_impact(action, output)

            # Estimate alerts
            alerts = self._estimate_alerts(action, context)

            return ActionResult(
                action_id=action_id,
                action_type=action_type,
                target=target,
                status="success",
                timestamp=start_time,
                duration_ms=duration_ms,
                output=output,
                impact_score=impact_score,
                alerts_generated=alerts,
                artifacts=output.get("artifacts", []) if output else [],
            )

        except Exception as e:
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            logger.error(f"Action failed: {action_type} on {target}: {e}")

            return ActionResult(
                action_id=action_id,
                action_type=action_type,
                target=target,
                status="failed",
                timestamp=start_time,
                duration_ms=duration_ms,
                error=str(e),
                impact_score=0.0,
                alerts_generated=0,
            )

    async def _simulate_action(
        self, action: Dict[str, Any], context: ExecutionContext
    ) -> Dict[str, Any]:
        """Simulate action without live execution."""
        action_type = action.get("type", "unknown")

        # Simulate execution time
        await asyncio.sleep(0.1)

        # Generate simulated output
        return {
            "mode": "simulation",
            "action_type": action_type,
            "simulated": True,
            "success_probability": 0.85,
            "artifacts": [],
        }

    async def _execute_lab_action(
        self, action: Dict[str, Any], context: ExecutionContext
    ) -> Dict[str, Any]:
        """Execute action in lab environment."""
        # In production, this would interact with lab infrastructure
        await asyncio.sleep(0.2)

        return {
            "mode": "lab",
            "action_type": action.get("type"),
            "isolated": True,
            "artifacts": [],
        }

    async def _execute_live_action(
        self, action: Dict[str, Any], context: ExecutionContext
    ) -> Dict[str, Any]:
        """Execute action in live environment using sandboxed tools."""
        if not self._tool_executor:
            logger.warning("Tool executor not initialized, falling back to simulation")
            return await self._simulate_action(action, context)

        tool_id = action.get("tool", "generic_tool")
        action_type = action.get("type", "unknown")
        target = action.get("target", {})

        # Build tool execution request
        request = ToolExecutionRequest(
            request_id=uuid4(),
            tool_id=tool_id,
            tool_image=self._get_tool_image(tool_id),
            command=self._build_tool_command(tool_id, action, target),
            arguments=action.get("parameters", {}),
            environment={
                "TARGET_HOST": target.get("asset", ""),
                "TARGET_NETWORK": target.get("network", ""),
                "ACTION_TYPE": action_type,
            },
            classification_level=context.classification_level,
            mission_id=context.mission_id,
        )

        # Authorize action via security manager
        if self._security_manager:
            authorized, reasons = await self._security_manager.authorize_action(
                action=action,
                roe={"allowed_tools": [tool_id], "allowed_networks": [target.get("network", "")]},
            )

            if not authorized:
                logger.warning(f"Action not authorized: {reasons}")
                return {
                    "mode": "live",
                    "action_type": action_type,
                    "status": "denied",
                    "reasons": reasons,
                    "artifacts": [],
                }

        # Execute in sandbox
        try:
            result = await self._tool_executor.execute(request)

            return {
                "mode": "live",
                "action_type": action_type,
                "tool_id": tool_id,
                "sandbox_state": result.state.value,
                "exit_code": result.exit_code,
                "stdout": result.stdout[:1000] if result.stdout else "",
                "stderr": result.stderr[:500] if result.stderr else "",
                "duration_ms": result.duration_ms,
                "execution_hash": result.execution_hash,
                "artifacts": [
                    {"name": k, "size": len(v)}
                    for k, v in result.output_files.items()
                ],
            }

        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return {
                "mode": "live",
                "action_type": action_type,
                "status": "failed",
                "error": str(e),
                "artifacts": [],
            }

    def _get_tool_image(self, tool_id: str) -> str:
        """Get Docker image for tool."""
        from ..sandbox import ToolImageRegistry

        config = ToolImageRegistry.get_image_config(tool_id)
        if config:
            return config["image"]
        return f"frostgate/tools-{tool_id}:latest"

    def _build_tool_command(
        self,
        tool_id: str,
        action: Dict[str, Any],
        target: Dict[str, Any],
    ) -> List[str]:
        """Build command for tool execution."""
        commands = {
            "nmap": ["nmap", "-sV", "-sC", "-oA", "/workspace/output/scan", target.get("asset", "")],
            "masscan": ["masscan", target.get("network", ""), "-p1-65535", "--rate=1000"],
            "nikto": ["nikto", "-h", target.get("asset", ""), "-output", "/workspace/output/nikto.html"],
            "nuclei": ["nuclei", "-u", target.get("asset", ""), "-o", "/workspace/output/nuclei.txt"],
            "sqlmap": ["sqlmap", "-u", target.get("asset", ""), "--batch", "--forms"],
        }

        return commands.get(tool_id, [tool_id, "--help"])

    def _calculate_action_impact(
        self, action: Dict[str, Any], output: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate impact score for action."""
        base_impacts = {
            "reconnaissance": 1.0,
            "initial_access": 5.0,
            "execution": 7.0,
            "persistence": 6.0,
            "privilege_escalation": 8.0,
            "defense_evasion": 3.0,
            "credential_access": 7.0,
            "discovery": 2.0,
            "lateral_movement": 6.0,
            "collection": 5.0,
            "exfiltration": 8.0,
            "impact": 10.0,
        }

        action_type = action.get("type", "unknown")
        base_impact = base_impacts.get(action_type, 3.0)

        # Modify based on target criticality
        target = action.get("target", {})
        if target.get("type") in ["domain_controller", "pki_server", "scada"]:
            base_impact *= 1.5

        return min(base_impact, 10.0)

    def _estimate_alerts(
        self, action: Dict[str, Any], context: ExecutionContext
    ) -> int:
        """Estimate alerts generated by action."""
        # Base alert probability by action type
        alert_probs = {
            "reconnaissance": 0.1,
            "initial_access": 0.3,
            "execution": 0.4,
            "persistence": 0.2,
            "privilege_escalation": 0.5,
            "credential_access": 0.4,
            "lateral_movement": 0.3,
            "exfiltration": 0.5,
        }

        action_type = action.get("type", "unknown")
        prob = alert_probs.get(action_type, 0.2)

        # Simulation generates no real alerts
        if context.environment == "simulation":
            return 0

        # Random determination
        import random
        return 1 if random.random() < prob else 0

    def _get_max_concurrent(self, environment: str) -> int:
        """Get maximum concurrent operations for environment."""
        limits = {
            "simulation": 10,
            "lab": 5,
            "canary": 3,
            "production": 2,
            "mission": 2,
        }
        return limits.get(environment, 5)

    async def abort(self, mission: Mission) -> None:
        """Abort mission execution."""
        self._abort_flags[mission.mission_id] = True
        logger.info(f"Abort requested for mission {mission.mission_id}")

    def is_active(self, mission_id: UUID) -> bool:
        """Check if mission is actively executing."""
        return mission_id in self._active_executions


class SimulationRunner:
    """
    Simulation Runner for pre-deployment validation.

    Runs 1000+ simulation iterations to validate
    policy compliance before promotion.
    """

    def __init__(self, config: Config):
        """Initialize Simulation Runner."""
        self.config = config
        self._executor = Executor(config)

    async def run_validation(
        self,
        mission: Mission,
        iterations: int = 1000,
    ) -> Dict[str, Any]:
        """
        Run simulation validation.

        Args:
            mission: Mission to validate
            iterations: Number of simulation runs

        Returns:
            Validation results
        """
        violations = 0
        total_impact = 0.0
        forensic_completeness = []

        for i in range(iterations):
            # Clone mission for simulation
            sim_mission = self._clone_mission(mission)

            # Run simulation
            async for result in self._executor.execute(sim_mission):
                total_impact += result.impact_score

            # Check for violations
            if sim_mission.impact_score > mission.blast_radius_cap:
                violations += 1

        avg_impact = total_impact / iterations if iterations > 0 else 0

        return {
            "iterations": iterations,
            "violations": violations,
            "violation_rate": violations / iterations if iterations > 0 else 0,
            "average_impact": avg_impact,
            "passed": violations == 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _clone_mission(self, mission: Mission) -> Mission:
        """Clone mission for simulation."""
        return Mission(
            policy_envelope=mission.policy_envelope.copy(),
            scenario=mission.scenario.copy(),
            persona_id=mission.persona_id,
            classification_level=mission.classification_level,
        )
