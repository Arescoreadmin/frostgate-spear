"""
Frost Gate Spear - Simulation and Execution Engine

Executes attack plans in simulation or live environments with
sandboxed tool execution via Docker isolation.

v6.1 EXECUTION CONTROL PLANE ENFORCEMENT:
All action execution MUST flow through validate_and_execute_action().
Direct invocation of execute methods is a SECURITY FAILURE.

v6.1 SECURITY HARDENING:
Uses non-forgeable execution tokens (secrets.token_urlsafe(32)) in addition
to context variables. Token MUST be validated before execution proceeds.
This is NOT crypto, but much harder to spoof than context variables alone.
"""

import asyncio
import contextvars
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.exceptions import GuardBypassError
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

if TYPE_CHECKING:
    from ..core.engine import ActionContext, ExecutionControlPlane, DecisionRecord

# Type alias for action_runner callable
# This MUST be validate_and_execute_action from ExecutionControlPlane
ActionRunner = Callable[["ActionContext"], Awaitable[Tuple["DecisionRecord", Optional[Dict[str, Any]]]]]

logger = logging.getLogger(__name__)


# Context variable to track legitimate execution paths
# This is set by the execution control plane when invoking the executor
_legitimate_execution: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "legitimate_execution", default=False
)

# Context variable to store the current DecisionRecord for execution tracking
_current_decision_record: contextvars.ContextVar[Optional["DecisionRecord"]] = contextvars.ContextVar(
    "current_decision_record", default=None
)

# Context variable to store the execution token for validation
_current_execution_token: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_execution_token", default=None
)

# Context variable to store the action_id for token validation
_current_action_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_action_id", default=None
)

# Reference to the control plane for token validation
_control_plane_ref: contextvars.ContextVar[Optional["ExecutionControlPlane"]] = contextvars.ContextVar(
    "control_plane_ref", default=None
)


def mark_legitimate_execution(
    decision_record: Optional["DecisionRecord"] = None,
    execution_token: Optional[str] = None,
    action_id: Optional[str] = None,
    control_plane: Optional["ExecutionControlPlane"] = None,
):
    """
    Mark the current execution context as legitimate.

    This MUST be called by the execution control plane before invoking
    any execution methods. Direct callers will not have this set.

    v6.1 SECURITY: Now requires execution token for validation.
    """
    _legitimate_execution.set(True)
    if decision_record:
        _current_decision_record.set(decision_record)
    if execution_token:
        _current_execution_token.set(execution_token)
    if action_id:
        _current_action_id.set(action_id)
    if control_plane:
        _control_plane_ref.set(control_plane)


def clear_legitimate_execution():
    """Clear the legitimate execution marker after execution completes."""
    _legitimate_execution.set(False)
    _current_decision_record.set(None)
    _current_execution_token.set(None)
    _current_action_id.set(None)
    _control_plane_ref.set(None)


def is_legitimate_execution() -> bool:
    """Check if the current execution is legitimate (via control plane)."""
    return _legitimate_execution.get()


def get_current_decision_record() -> Optional["DecisionRecord"]:
    """Get the current DecisionRecord if available."""
    return _current_decision_record.get()


def get_current_execution_token() -> Optional[str]:
    """Get the current execution token if available."""
    return _current_execution_token.get()


def _validate_execution_token() -> bool:
    """
    Validate the execution token with the control plane.

    Returns True if token is valid, False otherwise.
    This provides a non-forgeable check beyond context variables.
    """
    token = _current_execution_token.get()
    action_id = _current_action_id.get()
    control_plane = _control_plane_ref.get()

    if token is None or action_id is None:
        logger.warning("Execution token or action_id not set")
        return False

    if control_plane is None:
        logger.warning("Control plane reference not set - cannot validate token")
        return False

    return control_plane.validate_execution_token(
        token=token,
        action_id=action_id,
        consume=False,
    )


def _check_bypass() -> None:
    """
    Check if execution is bypassing the control plane.

    v6.1 SECURITY: Now requires BOTH context variable AND token validation.
    Raises GuardBypassError if bypass is detected.

    v6.1 FORENSICS: Emits forensic event BEFORE raising error to ensure
    all bypass attempts are logged even if exception handling suppresses.
    """
    import inspect

    # Get caller info for forensics
    caller_frame = inspect.currentframe()
    caller_info = "unknown"
    if caller_frame and caller_frame.f_back:
        frame = caller_frame.f_back
        caller_info = f"{frame.f_code.co_filename}:{frame.f_lineno}:{frame.f_code.co_name}"

    # Check 1: Context variable (can be spoofed, but provides defense in depth)
    if not is_legitimate_execution():
        # FORENSIC: Log bypass attempt before raising
        logger.critical(
            f"CONTROL PLANE BYPASS DETECTED: direct_executor_invocation - "
            f"caller={caller_info} legitimate_execution=False"
        )
        raise GuardBypassError(
            message="Action execution attempted without passing through validate_and_execute_action()",
            bypass_path="direct_executor_invocation",
            caller=caller_info,
        )

    # Check 2: Control plane reference (required for token validation)
    control_plane = _control_plane_ref.get()
    if control_plane is None:
        logger.critical(
            f"CONTROL PLANE BYPASS DETECTED: missing_control_plane_reference - "
            f"caller={caller_info}"
        )
        raise GuardBypassError(
            message="Action execution attempted without control plane reference",
            bypass_path="missing_control_plane_reference",
            caller=caller_info,
        )

    # Check 3: Execution token (requires valid token from control plane)
    token = get_current_execution_token()
    if token is None:
        # FORENSIC: Log bypass attempt before raising
        logger.critical(
            f"CONTROL PLANE BYPASS DETECTED: missing_execution_token - "
            f"caller={caller_info} token=None"
        )
        raise GuardBypassError(
            message="Action execution attempted without valid execution token",
            bypass_path="missing_execution_token",
            caller=caller_info,
        )

    action_id = _current_action_id.get()
    if action_id is None:
        logger.critical(
            f"CONTROL PLANE BYPASS DETECTED: missing_action_id - "
            f"caller={caller_info}"
        )
        raise GuardBypassError(
            message="Action execution attempted without action_id",
            bypass_path="missing_action_id",
            caller=caller_info,
        )

    if not _validate_execution_token():
        logger.critical(
            f"CONTROL PLANE BYPASS DETECTED: invalid_execution_token - "
            f"caller={caller_info}"
        )
        raise GuardBypassError(
            message="Action execution attempted with invalid execution token",
            bypass_path="token_validation_failed",
            caller=caller_info,
        )


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

    def _emit_bypass_forensic_event(
        self,
        mission_id: UUID,
        bypass_path: str,
        details: Dict[str, Any],
    ) -> None:
        """
        Emit a forensic event for bypass attempts.

        v6.1 SECURITY: ALL bypass attempts MUST be logged for forensic analysis.
        This is a non-blocking call - bypass is logged even if emission fails.

        Args:
            mission_id: The mission where bypass was attempted
            bypass_path: Identifier of the bypass path attempted
            details: Additional context about the bypass attempt
        """
        event = {
            "event_type": "BYPASS_ATTEMPT",
            "timestamp": datetime.utcnow().isoformat(),
            "mission_id": str(mission_id),
            "bypass_path": bypass_path,
            "severity": "CRITICAL",
            "details": details,
        }
        # Critical: Always log bypass attempts
        logger.critical(
            f"CONTROL PLANE BYPASS ATTEMPTED: {bypass_path} - "
            f"mission={mission_id} details={details}"
        )
        # In production, this would emit to a forensic event bus
        # For now, ensure it's logged at CRITICAL level

    async def execute(
        self,
        mission: Mission,
        action_runner: Optional[ActionRunner] = None,
        expected_control_plane: Optional["ExecutionControlPlane"] = None,
    ) -> AsyncGenerator[ActionResult, None]:
        """
        Execute mission plan.

        v6.1 SECURITY: action_runner is REQUIRED.
        SIM MUST NOT execute tools directly - ALL execution MUST flow through
        the engine's ExecutionControlPlane.validate_and_execute_action().

        Args:
            mission: Mission to execute
            action_runner: REQUIRED callable that routes action execution through
                          the ExecutionControlPlane. This MUST be
                          control_plane.validate_and_execute_action.
                          If None or missing, raises GuardBypassError.
            expected_control_plane: The control plane instance expected to own
                          the action_runner for this mission.

        Yields:
            Action results as they complete

        Raises:
            GuardBypassError: If action_runner is not provided (bypass attempt)
        """
        # v6.1 MANDATORY: action_runner is REQUIRED
        # SIM cannot execute without delegation to the control plane
        if action_runner is None:
            self._emit_bypass_forensic_event(
                mission_id=mission.mission_id,
                bypass_path="execute_without_action_runner",
                details={"method": "execute", "mission_id": str(mission.mission_id)},
            )
            raise GuardBypassError(
                message="Executor.execute() called without action_runner. "
                        "ALL execution MUST flow through ExecutionControlPlane.validate_and_execute_action()",
                bypass_path="execute_without_action_runner",
                caller="Executor.execute",
            )
        else:
            from ..core.engine import ExecutionControlPlane

            runner_owner = getattr(action_runner, "__self__", None)
            if (
                runner_owner is None
                or not isinstance(runner_owner, ExecutionControlPlane)
                or getattr(action_runner, "__name__", "") != "validate_and_execute_action"
            ):
                self._emit_bypass_forensic_event(
                    mission_id=mission.mission_id,
                    bypass_path="execute_with_untrusted_action_runner",
                    details={"method": "execute", "mission_id": str(mission.mission_id)},
                )
                raise GuardBypassError(
                    message="Executor.execute() called with untrusted action_runner. "
                            "ALL execution MUST flow through ExecutionControlPlane.validate_and_execute_action()",
                    bypass_path="execute_with_untrusted_action_runner",
                    caller="Executor.execute",
                )
            if expected_control_plane is not None and runner_owner is not expected_control_plane:
                self._emit_bypass_forensic_event(
                    mission_id=mission.mission_id,
                    bypass_path="execute_with_mismatched_control_plane",
                    details={"method": "execute", "mission_id": str(mission.mission_id)},
                )
                raise GuardBypassError(
                    message="Executor.execute() called with action_runner from a different control plane instance.",
                    bypass_path="execute_with_mismatched_control_plane",
                    caller="Executor.execute",
                )

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

                # Execute phase actions via action_runner (control plane)
                async for result in self._execute_phase(phase, context, mission, action_runner):
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
        action_runner: ActionRunner,
    ) -> AsyncGenerator[ActionResult, None]:
        """
        Execute single phase.

        v6.1 SECURITY: action_runner is REQUIRED.
        All action execution MUST flow through the control plane.
        """
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
                    semaphore, action, context, mission, action_runner
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
        action_runner: ActionRunner,
    ) -> Optional[ActionResult]:
        """
        Execute action with semaphore for concurrency control.

        v6.1 SECURITY: All execution MUST go through action_runner.
        This method builds an ActionContext and delegates to the control plane.
        Direct calls to _execute_action are NOT allowed.
        """
        async with semaphore:
            return await self._delegate_to_control_plane(
                action, context, mission, action_runner
            )

    async def _delegate_to_control_plane(
        self,
        action: Dict[str, Any],
        context: ExecutionContext,
        mission: Mission,
        action_runner: ActionRunner,
    ) -> Optional[ActionResult]:
        """
        Delegate action execution to the control plane via action_runner.

        v6.1 SECURITY: This is the ONLY path for action execution.
        Direct calls to _execute_action or _tool_executor.execute are BLOCKED.

        Args:
            action: Action to execute
            context: Execution context
            mission: Mission being executed
            action_runner: Control plane's validate_and_execute_action

        Returns:
            ActionResult from the control plane execution
        """
        from ..core.engine import ActionContext

        action_id = action.get("action_id", str(uuid4()))
        action_type = action.get("type", "unknown")
        target = action.get("target", {})
        start_time = datetime.utcnow()

        try:
            # Build ActionContext for the control plane
            ctx = ActionContext(
                tenant_id=str(mission.policy_envelope.get("tenant_id", "default")),
                campaign_id=str(mission.mission_id),
                mode=context.environment.upper() if context.environment else "SIM",
                risk_tier=mission.policy_envelope.get("risk_tier", 1),
                scope_id=mission.policy_envelope.get("scope_id", str(mission.mission_id)),
                action=action,
                target=target,
                entrypoint=mission.policy_envelope.get("entrypoint", {}),
                permit=mission.policy_envelope.get("permit", {
                    "permit_id": f"exec-permit-{mission.mission_id}",
                    "mode": context.environment.upper() if context.environment else "SIM",
                    "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
                }),
                action_id=action_id,
                classification_level=context.classification_level,
            )

            # Delegate to control plane (THE ONLY AUTHORIZED PATH)
            record, result = await action_runner(ctx)

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Build ActionResult from control plane response
            if record.executed and result:
                impact_score = result.get("impact_score", self._calculate_action_impact(action, result))
                alerts = result.get("alerts_generated", self._estimate_alerts(action, context))

                return ActionResult(
                    action_id=UUID(action_id) if isinstance(action_id, str) else action_id,
                    action_type=action_type,
                    target=target.get("asset", "unknown"),
                    status="success",
                    timestamp=start_time,
                    duration_ms=duration_ms,
                    output=result,
                    impact_score=impact_score,
                    alerts_generated=alerts,
                    artifacts=result.get("artifacts", []),
                )
            else:
                # Control plane blocked the action
                return ActionResult(
                    action_id=UUID(action_id) if isinstance(action_id, str) else action_id,
                    action_type=action_type,
                    target=target.get("asset", "unknown"),
                    status="blocked",
                    timestamp=start_time,
                    duration_ms=duration_ms,
                    error=record.error or "Action blocked by control plane",
                    impact_score=0.0,
                    alerts_generated=0,
                )

        except Exception as e:
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            logger.error(f"Action execution via control plane failed: {action_type} - {e}")

            return ActionResult(
                action_id=UUID(action_id) if isinstance(action_id, str) else action_id,
                action_type=action_type,
                target=target.get("asset", "unknown"),
                status="failed",
                timestamp=start_time,
                duration_ms=duration_ms,
                error=str(e),
                impact_score=0.0,
                alerts_generated=0,
            )

    async def _execute_action(
        self,
        action: Dict[str, Any],
        context: ExecutionContext,
        mission: Mission,
    ) -> ActionResult:
        """
        Execute single action.

        v6.1 SECURITY: This method MUST only be called through the
        execution control plane. Direct calls will raise GuardBypassError.
        """
        # v6.1 BYPASS PREVENTION: Verify this is a legitimate execution path
        _check_bypass()

        action_id_raw = action.get("action_id", str(uuid4()))
        if isinstance(action_id_raw, UUID):
            action_id = action_id_raw
        else:
            try:
                action_id = UUID(str(action_id_raw))
            except (ValueError, TypeError):
                action_id = uuid4()
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
        """
        Execute action in live environment using sandboxed tools.

        v6.1 SECURITY: This method MUST only be called through the
        execution control plane. Direct calls will raise GuardBypassError.
        """
        # v6.1 BYPASS PREVENTION: Verify this is a legitimate execution path
        _check_bypass()

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

    v6.1 SECURITY: ALL execution MUST go through the ExecutionControlPlane.
    This class uses validate_and_execute_action() for each action.
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

        v6.1 SECURITY: Uses ExecutionControlPlane for all action execution.
        Direct executor invocation is NOT allowed.

        Args:
            mission: Mission to validate
            iterations: Number of simulation runs

        Returns:
            Validation results
        """
        from ..core.engine import (
            ActionContext,
            ExecutionControlPlane,
            get_execution_control_plane,
            validate_and_execute_action,
        )

        violations = 0
        total_impact = 0.0
        forensic_completeness = []

        # Get or create execution control plane for simulation
        ecp = get_execution_control_plane()
        ecp._test_mode = True  # Enable test mode for simulations

        for i in range(iterations):
            # Clone mission for simulation
            sim_mission = self._clone_mission(mission)

            if not sim_mission.plan:
                continue

            # Execute each action through the control plane
            for phase in sim_mission.plan.phases:
                for action in phase.get("actions", []):
                    try:
                        # Build ActionContext for control plane
                        ctx = ActionContext(
                            tenant_id=str(sim_mission.policy_envelope.get("tenant_id", "sim")),
                            campaign_id=str(sim_mission.mission_id),
                            mode="SIM",  # Always SIM mode for validation
                            risk_tier=sim_mission.policy_envelope.get("risk_tier", 1),
                            scope_id=sim_mission.policy_envelope.get("scope_id", "sim-scope"),
                            action=action,
                            target=action.get("target", {}),
                            entrypoint=sim_mission.policy_envelope.get("entrypoint", {}),
                            permit=sim_mission.policy_envelope.get("permit", {
                                "permit_id": f"sim-permit-{i}",
                                "mode": "SIM",
                                "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
                            }),
                        )

                        # Execute through control plane (THE ONLY AUTHORIZED PATH)
                        record, result = await validate_and_execute_action(ctx)

                        if result:
                            total_impact += result.get("impact_score", 0)

                    except Exception as e:
                        # Log but continue - simulations should be resilient
                        logger.debug(f"Simulation action failed: {e}")

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
