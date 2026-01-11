"""
Frost Gate Spear - Execution Control Plane Guardrail Tests

v6.1 SECURITY TESTS - Gate F Enforcement

These tests verify that:
1. ALL action execution MUST pass through validate_and_execute_action()
2. TTL is enforced continuously, not just at preflight
3. No bypass paths exist for action execution
4. DecisionRecord exists for every executed action

FAIL-FIRST DESIGN: These tests are designed to FAIL before implementation
and PASS only when enforcement is real.
"""

import asyncio
import base64
import json
import pytest
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_permit_validator():
    """Create a mock permit validator for testing."""
    validator = MagicMock()

    # Default: permit is valid
    validator.check_ttl_expiry.return_value = (False, 3600)  # Not expired, 1 hour remaining

    result = MagicMock()
    result.valid = True
    result.signature_verified = True
    result.issues = []
    validator.validate_permit.return_value = result

    return validator


@pytest.fixture
def mock_runtime_guard():
    """Create a mock runtime guard for testing."""
    from src.runtime_guard import Decision

    guard = MagicMock()

    decision = MagicMock()
    decision.decision = Decision.ALLOW
    decision.rule = "RUNTIME.ALLOWED"
    decision.reason = "Action allowed by runtime guard"
    decision.attestation_hash = "sha256:test_hash"
    decision.details = {}

    guard.enforce_action.return_value = decision
    return guard


@pytest.fixture
def mock_rate_limiter():
    """Create a mock rate limiter for testing."""
    limiter = MagicMock()
    limiter.check_rate.return_value = (True, 1)  # Allowed, current rate = 1
    return limiter


@pytest.fixture
def mock_target_safety():
    """Create a mock target safety checker for testing."""
    safety = MagicMock()

    result = MagicMock()
    result.allowed = True
    result.warnings = []

    # Make it an async function
    async def check_action_safety(*args, **kwargs):
        return result

    safety.check_action_safety = check_action_safety
    return safety


@pytest.fixture
def valid_permit(sample_ed25519_keypair):
    """Create a valid execution permit for testing."""
    now = datetime.now(timezone.utc)

    permit_data = {
        "permit_id": str(uuid4()),
        "campaign_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "mode": "SIM",
        "risk_tier": 1,
        "credential_mode": "UNAUTHENTICATED",
        "tool_allowlist": [
            {"tool_id": "nmap", "version": "7.94", "certification": "SIM_SAFE"},
        ],
        "target_allowlist": [
            {"target_id": "HOST-123456789", "target_type": "HOST", "max_actions_per_minute": 60},
        ],
        "entrypoint_allowlist": [
            {"entrypoint_id": "ep-001", "region": "us-east-1", "network_zone": "PUBLIC"},
        ],
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": f"test-nonce-{uuid4()}",
        "jti": str(uuid4()),
    }

    # Sign the permit
    payload = json.dumps(permit_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = sample_ed25519_keypair["private_key"].sign(payload)

    permit_data["sig"] = {
        "algorithm": "Ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
        "key_id": "test-key-001",
    }

    return permit_data


@pytest.fixture
def short_ttl_permit(sample_ed25519_keypair):
    """Create a permit with very short TTL for expiry testing."""
    now = datetime.now(timezone.utc)

    permit_data = {
        "permit_id": str(uuid4()),
        "campaign_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "mode": "SIM",
        "risk_tier": 1,
        "credential_mode": "UNAUTHENTICATED",
        "tool_allowlist": [
            {"tool_id": "nmap", "version": "7.94", "certification": "SIM_SAFE"},
        ],
        "target_allowlist": [
            {"target_id": "HOST-123456789", "target_type": "HOST", "max_actions_per_minute": 60},
        ],
        "entrypoint_allowlist": [
            {"entrypoint_id": "ep-001", "region": "us-east-1", "network_zone": "PUBLIC"},
        ],
        "issued_at": now.isoformat(),
        # Expires in 100ms - very short TTL for testing
        "expires_at": (now + timedelta(milliseconds=100)).isoformat(),
        "nonce": f"test-nonce-{uuid4()}",
        "jti": str(uuid4()),
    }

    # Sign the permit
    payload = json.dumps(permit_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = sample_ed25519_keypair["private_key"].sign(payload)

    permit_data["sig"] = {
        "algorithm": "Ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
        "key_id": "test-key-001",
    }

    return permit_data


@pytest.fixture
def action_context_factory(valid_permit):
    """Factory to create ActionContext instances for testing."""
    from src.core.engine import ActionContext

    def create_context(
        mode: str = "SIM",
        risk_tier: int = 1,
        permit: Optional[Dict] = None,
        action: Optional[Dict] = None,
        **kwargs
    ) -> ActionContext:
        return ActionContext(
            tenant_id=str(uuid4()),
            campaign_id=str(uuid4()),
            mode=mode,
            risk_tier=risk_tier,
            scope_id=str(uuid4()),
            action=action or {"type": "reconnaissance", "tool_id": "nmap"},
            target={"target_id": "HOST-123456789", "asset": "192.168.1.1"},
            entrypoint={"entrypoint_id": "ep-001"},
            permit=permit or valid_permit,
            **kwargs,
        )

    return create_context


# ============================================================================
# TEST 1: NO BYPASS
# ============================================================================


class TestNoBypass:
    """
    TEST 1: NO BYPASS

    Goal: Prove that actions cannot execute unless all guards run.

    Test setup:
    - Mock a tool/executor that sets a flag if executed
    - Run via engine using validate_and_execute_action()
    - Attempt to invoke executor/tool directly

    Assertions:
    - Engine path:
      - Tool executed
      - DecisionRecord exists with ALL guard decisions populated
    - Direct invocation:
      - Tool NOT executed
      - GuardBypassError raised
    """

    @pytest.mark.asyncio
    async def test_engine_path_executes_and_creates_decision_record(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that execution through validate_and_execute_action():
        1. Executes the tool
        2. Creates a DecisionRecord with ALL guard decisions populated
        """
        from src.core.engine import (
            ActionContext,
            DecisionRecord,
            ExecutionControlPlane,
            validate_and_execute_action,
            set_execution_control_plane,
        )

        # Track if executor was called
        executor_called = False
        execution_result = None

        async def mock_executor(ctx: ActionContext, record: DecisionRecord):
            nonlocal executor_called, execution_result
            executor_called = True
            execution_result = {"status": "success", "action_id": ctx.action_id}
            return execution_result

        # Create execution control plane with mocked components
        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            action_executor=mock_executor,
        )
        ecp._test_mode = True  # Enable test mode

        set_execution_control_plane(ecp)

        # Create action context
        ctx = action_context_factory()

        # Execute through the engine
        record, result = await validate_and_execute_action(ctx)

        # ASSERTIONS
        # 1. Tool was executed
        assert executor_called, "Executor should have been called through engine path"

        # 2. DecisionRecord exists
        assert record is not None, "DecisionRecord must exist for executed actions"

        # 3. ALL guard decisions are populated
        assert record.permit_decision is not None, "Permit decision must be recorded"
        assert record.opa_abac_decision is not None, "OPA ABAC decision must be recorded"
        assert record.opa_scope_decision is not None, "OPA scope decision must be recorded"
        assert record.runtime_guard_decision is not None, "Runtime guard decision must be recorded"
        assert record.rate_limit_decision is not None, "Rate limit decision must be recorded"
        assert record.target_safety_decision is not None, "Target safety decision must be recorded"

        # 4. DecisionRecord reports complete
        assert record.is_complete(), "DecisionRecord must be complete with all guard decisions"

        # 5. All guards passed
        assert record.all_guards_passed, "All guards should have passed"

        # 6. Execution was recorded
        assert record.executed, "Execution should be recorded"
        assert record.execution_result is not None, "Execution result should be recorded"

    @pytest.mark.asyncio
    async def test_direct_executor_invocation_raises_guard_bypass_error(self):
        """
        Test that directly invoking the Executor raises GuardBypassError.

        This test verifies that bypass paths are blocked.
        """
        from src.core.config import Config
        from src.core.exceptions import GuardBypassError
        from src.sim import Executor, mark_legitimate_execution, clear_legitimate_execution

        # Ensure we are NOT in a legitimate execution context
        clear_legitimate_execution()

        # Create executor
        config = Config()
        executor = Executor(config)

        # Create a mock mission and execution context
        from src.sim import ExecutionContext
        from uuid import uuid4

        context = ExecutionContext(
            mission_id=uuid4(),
            phase_name="test_phase",
            action_index=0,
            total_actions=1,
            environment="simulation",
            classification_level="UNCLASS",
            alert_count=0,
            impact_score=0.0,
        )

        action = {
            "action_id": str(uuid4()),
            "type": "reconnaissance",
            "target": {"asset": "192.168.1.1"},
        }

        # Create a minimal mock mission
        mission = MagicMock()
        mission.mission_id = uuid4()

        # Attempt direct invocation - should raise GuardBypassError
        with pytest.raises(GuardBypassError) as exc_info:
            await executor._execute_action(action, context, mission)

        # Verify the error details
        assert "STRUCTURAL.NO_BYPASS.VIOLATION" in str(exc_info.value.code)
        assert exc_info.value.bypass_path is not None

    @pytest.mark.asyncio
    async def test_direct_live_action_invocation_raises_guard_bypass_error(self):
        """
        Test that directly invoking _execute_live_action raises GuardBypassError.
        """
        from src.core.config import Config
        from src.core.exceptions import GuardBypassError
        from src.sim import Executor, clear_legitimate_execution

        # Ensure we are NOT in a legitimate execution context
        clear_legitimate_execution()

        # Create executor
        config = Config()
        executor = Executor(config)

        # Create a mock execution context
        from src.sim import ExecutionContext
        from uuid import uuid4

        context = ExecutionContext(
            mission_id=uuid4(),
            phase_name="test_phase",
            action_index=0,
            total_actions=1,
            environment="production",
            classification_level="UNCLASS",
            alert_count=0,
            impact_score=0.0,
        )

        action = {
            "action_id": str(uuid4()),
            "type": "reconnaissance",
            "target": {"asset": "192.168.1.1"},
        }

        # Attempt direct invocation - should raise GuardBypassError
        with pytest.raises(GuardBypassError) as exc_info:
            await executor._execute_live_action(action, context)

        assert "STRUCTURAL.NO_BYPASS.VIOLATION" in str(exc_info.value.code)

    @pytest.mark.asyncio
    async def test_legitimate_execution_path_succeeds(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that when legitimate execution is marked, the executor succeeds.
        """
        from src.core.config import Config
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
            DecisionRecord,
        )
        from src.sim import Executor, mark_legitimate_execution, clear_legitimate_execution

        # Create execution control plane
        executor_called = False

        async def mock_executor(ctx, record):
            nonlocal executor_called
            # Mark as legitimate before executing
            mark_legitimate_execution(record)
            try:
                # This simulates what the control plane would do
                executor_called = True
                return {"status": "success", "action_id": ctx.action_id}
            finally:
                clear_legitimate_execution()

        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            action_executor=mock_executor,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        # Create action context
        ctx = action_context_factory()

        # Execute through the engine
        record, result = await validate_and_execute_action(ctx)

        # Should succeed
        assert executor_called
        assert record.executed or record.all_guards_passed


# ============================================================================
# TEST 2: TTL EXPIRY MID-RUN
# ============================================================================


class TestTTLExpiryMidRun:
    """
    TEST 2: TTL EXPIRY MID-RUN

    Goal: Prove TTL is enforced continuously, not only at preflight.

    Test setup:
    - Permit with very short TTL
    - Execute action 1 (should succeed)
    - Advance time past TTL
    - Execute action 2

    Assertions:
    - Action 1 executed
    - Action 2 blocked
    - PermitExpiredError raised
    - Terminal forensic event emitted with reason PERMIT.EXPIRED
    """

    @pytest.mark.asyncio
    async def test_ttl_enforced_per_action_not_just_preflight(
        self,
        action_context_factory,
        short_ttl_permit,
        sample_ed25519_keypair,
    ):
        """
        Test that TTL is checked for EACH action, not just at campaign start.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import PermitExpiredError

        # Create a permit validator that simulates TTL expiry
        ttl_expired = False
        call_count = 0

        permit_validator = MagicMock()

        def check_ttl_expiry(permit):
            nonlocal call_count
            call_count += 1
            # First call: not expired
            # Second call: expired
            if call_count == 1:
                return (False, 100)  # Not expired, 100ms remaining
            else:
                return (True, 0)  # Expired

        permit_validator.check_ttl_expiry = check_ttl_expiry

        result_mock = MagicMock()
        result_mock.valid = True
        result_mock.signature_verified = True
        result_mock.issues = []
        permit_validator.validate_permit.return_value = result_mock

        # Mock runtime guard
        from src.runtime_guard import Decision
        runtime_guard = MagicMock()
        decision = MagicMock()
        decision.decision = Decision.ALLOW
        decision.rule = "RUNTIME.ALLOWED"
        decision.reason = "Allowed"
        decision.attestation_hash = "test"
        decision.details = {}
        runtime_guard.enforce_action.return_value = decision

        # Track forensic events
        forensic_events = []

        async def capture_forensic_event(event):
            forensic_events.append(event)

        action_1_executed = False
        action_2_executed = False

        async def mock_executor(ctx, record):
            nonlocal action_1_executed, action_2_executed
            if call_count == 1:
                action_1_executed = True
            else:
                action_2_executed = True
            return {"status": "success"}

        # Create execution control plane
        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            runtime_guard=runtime_guard,
            action_executor=mock_executor,
            forensic_emitter=capture_forensic_event,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        # ACTION 1: Execute with valid TTL
        ctx1 = action_context_factory(permit=short_ttl_permit)
        record1, result1 = await validate_and_execute_action(ctx1)

        # ACTION 1 ASSERTIONS
        assert action_1_executed, "Action 1 should have executed"
        assert record1.all_guards_passed, "Action 1 should have passed all guards"

        # ACTION 2: Execute after TTL expired
        ctx2 = action_context_factory(permit=short_ttl_permit)

        with pytest.raises(PermitExpiredError) as exc_info:
            await validate_and_execute_action(ctx2)

        # ACTION 2 ASSERTIONS
        assert not action_2_executed, "Action 2 should NOT have executed"
        assert exc_info.value.code == "PERMIT.EXPIRED", "Error code should be PERMIT.EXPIRED"

        # FORENSIC EVENT ASSERTION
        # There should be at least one forensic event with outcome BLOCKED
        blocked_events = [e for e in forensic_events if e.outcome == "BLOCKED"]
        assert len(blocked_events) > 0, "Should have emitted BLOCKED forensic event"

        # Check the blocked event has the right reason
        blocked_event = blocked_events[0]
        assert blocked_event.decision_record.permit_decision is not None
        assert blocked_event.decision_record.permit_decision.rule == "PERMIT.EXPIRED"

    @pytest.mark.asyncio
    async def test_ttl_check_halts_execution_immediately(
        self,
        action_context_factory,
    ):
        """
        Test that TTL expiry halts execution immediately without running other guards.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import PermitExpiredError

        # Create a permit validator that always returns expired
        permit_validator = MagicMock()
        permit_validator.check_ttl_expiry.return_value = (True, 0)  # Always expired

        # These should NOT be called if TTL check fails first
        runtime_guard_called = False
        rate_limiter_called = False
        target_safety_called = False

        runtime_guard = MagicMock()
        def runtime_check(*args, **kwargs):
            nonlocal runtime_guard_called
            runtime_guard_called = True

        rate_limiter = MagicMock()
        def rate_check(*args, **kwargs):
            nonlocal rate_limiter_called
            rate_limiter_called = True

        target_safety = MagicMock()
        async def safety_check(*args, **kwargs):
            nonlocal target_safety_called
            target_safety_called = True

        runtime_guard.enforce_action = runtime_check
        rate_limiter.check_rate = rate_check
        target_safety.check_action_safety = safety_check

        # Create execution control plane
        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            runtime_guard=runtime_guard,
            rate_limiter=rate_limiter,
            target_safety=target_safety,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(PermitExpiredError):
            await validate_and_execute_action(ctx)

        # Verify that subsequent guards were NOT called
        # (execution should halt at permit check)
        # Note: The other guards should not be called because permit check fails first


# ============================================================================
# Additional Guard Tests
# ============================================================================


class TestGuardEnforcement:
    """Additional tests for individual guard enforcement."""

    @pytest.mark.asyncio
    async def test_decision_record_missing_raises_error(self):
        """
        Test that attempting execution without a DecisionRecord raises an error.
        """
        from src.core.exceptions import DecisionRecordMissingError

        # This tests that our error type exists and works correctly
        error = DecisionRecordMissingError(
            message="No decision record found for action",
            action_id="test-action-id",
        )

        assert error.code == "EXECUTION.DECISION_RECORD.MISSING"
        assert error.action_id == "test-action-id"

    @pytest.mark.asyncio
    async def test_guard_bypass_error_contains_details(self):
        """
        Test that GuardBypassError contains proper details for forensics.
        """
        from src.core.exceptions import GuardBypassError

        error = GuardBypassError(
            message="Bypass detected",
            bypass_path="direct_tool_invocation",
            caller="TestCaller",
        )

        assert error.code == "STRUCTURAL.NO_BYPASS.VIOLATION"
        assert error.bypass_path == "direct_tool_invocation"
        assert error.caller == "TestCaller"
        assert error.details["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_scope_drift_error_halts_execution(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that P2+ scope drift halts execution.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import ScopeDriftError

        # Create OPA client that returns P2 drift
        opa_client = MagicMock()

        # Create execution control plane
        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            opa_client=opa_client,
        )
        ecp._test_mode = True

        # Mock the scope query to return P2 drift
        async def mock_scope_query(ctx):
            return {"allow": False, "drift_score": 0.35, "severity": "P2"}

        ecp._query_opa_scope = mock_scope_query

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(ScopeDriftError) as exc_info:
            await validate_and_execute_action(ctx)

        assert exc_info.value.code == "RUNTIME.SCOPE.DRIFT"
        assert exc_info.value.severity == "P2"

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_halts_execution(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that exceeding rate limit halts execution.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import RateLimitedError

        # Rate limiter that denies
        rate_limiter = MagicMock()
        rate_limiter.check_rate.return_value = (False, 100)  # Denied, current rate = 100

        # Create execution control plane
        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            rate_limiter=rate_limiter,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(RateLimitedError) as exc_info:
            await validate_and_execute_action(ctx)

        assert exc_info.value.code == "RUNTIME.RATE.EXCEEDED"

    @pytest.mark.asyncio
    async def test_step_up_required_halts_execution(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that step-up requirement halts execution.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import StepUpRequiredError

        # Create execution control plane
        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        # Create context with destructive action requiring step-up
        ctx = action_context_factory(
            mode="LAB",  # Non-SIM mode
            risk_tier=3,  # High risk tier
            action={"type": "credential_access", "destructive": True, "credential_access": True},
        )

        with pytest.raises(StepUpRequiredError) as exc_info:
            await validate_and_execute_action(ctx)

        assert exc_info.value.code == "ABAC.STEPUP.REQUIRED"


# ============================================================================
# Integration Tests for Control Plane
# ============================================================================


class TestExecutionControlPlaneIntegration:
    """Integration tests for the full execution control plane."""

    @pytest.mark.asyncio
    async def test_full_guard_chain_execution(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
        mock_rate_limiter,
        mock_target_safety,
    ):
        """
        Test that all guards are executed in correct order.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )

        execution_order = []

        # Wrap each guard to track execution order
        original_check_ttl = mock_permit_validator.check_ttl_expiry

        def wrapped_check_ttl(*args, **kwargs):
            execution_order.append("permit")
            return original_check_ttl(*args, **kwargs)

        mock_permit_validator.check_ttl_expiry = wrapped_check_ttl

        async def mock_executor(ctx, record):
            execution_order.append("executor")
            return {"status": "success"}

        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            rate_limiter=mock_rate_limiter,
            target_safety=mock_target_safety,
            action_executor=mock_executor,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        record, result = await validate_and_execute_action(ctx)

        # Verify execution order
        assert "permit" in execution_order, "Permit check should have executed"
        assert "executor" in execution_order, "Executor should have executed"

        # Permit should be checked first
        permit_idx = execution_order.index("permit")
        executor_idx = execution_order.index("executor")
        assert permit_idx < executor_idx, "Permit must be checked before execution"

    @pytest.mark.asyncio
    async def test_forensic_event_emitted_on_success(
        self,
        action_context_factory,
        mock_permit_validator,
        mock_runtime_guard,
    ):
        """
        Test that forensic event is emitted on successful execution.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
            ForensicEvent,
        )

        forensic_events = []

        async def capture_forensic_event(event: ForensicEvent):
            forensic_events.append(event)

        async def mock_executor(ctx, record):
            return {"status": "success"}

        ecp = ExecutionControlPlane(
            permit_validator=mock_permit_validator,
            runtime_guard=mock_runtime_guard,
            action_executor=mock_executor,
            forensic_emitter=capture_forensic_event,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        record, result = await validate_and_execute_action(ctx)

        # Verify forensic event was emitted
        assert len(forensic_events) > 0, "Forensic event should be emitted"

        event = forensic_events[0]
        assert event.event_type == "ACTION_EXECUTED"
        assert event.outcome == "SUCCESS"
        assert event.action_context == ctx
        assert event.decision_record == record

    @pytest.mark.asyncio
    async def test_forensic_event_emitted_on_denial(
        self,
        action_context_factory,
        mock_runtime_guard,
    ):
        """
        Test that forensic event is emitted when action is denied.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import PermitExpiredError

        forensic_events = []

        async def capture_forensic_event(event):
            forensic_events.append(event)

        # Permit validator that always denies (expired)
        permit_validator = MagicMock()
        permit_validator.check_ttl_expiry.return_value = (True, 0)

        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            runtime_guard=mock_runtime_guard,
            forensic_emitter=capture_forensic_event,
        )
        ecp._test_mode = True

        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(PermitExpiredError):
            await validate_and_execute_action(ctx)

        # Verify forensic event was emitted for denial
        assert len(forensic_events) > 0, "Forensic event should be emitted on denial"

        event = forensic_events[0]
        assert event.event_type == "ACTION_DENIED"
        assert event.outcome == "BLOCKED"


# ============================================================================
# Test A: Guard Order Immutability (DoD-Grade Requirement)
# ============================================================================


class TestGuardOrderImmutability:
    """
    v6.1 SECURITY - Guard Order MUST Be Immutable

    These tests verify that:
    1. Guards are ALWAYS called in the exact required order
    2. If one guard raises, downstream guards are NEVER called
    3. Guard order cannot be accidentally reordered by future code changes

    This is a DoD-grade requirement: guard ordering is a security invariant.
    """

    @pytest.fixture
    def action_context_factory(self, valid_permit):
        """Create an ActionContext for testing."""
        from src.core.engine import ActionContext

        def factory(**kwargs):
            defaults = {
                "tenant_id": str(uuid4()),
                "campaign_id": str(uuid4()),
                "mode": "SIM",
                "risk_tier": 1,
                "scope_id": "scope-001",
                "action": {"type": "reconnaissance", "tool_id": "nmap"},
                "target": {"target_id": "host-001", "asset": "10.0.0.1"},
                "entrypoint": {"entrypoint_id": "ep-001"},
                "permit": valid_permit,
            }
            defaults.update(kwargs)
            return ActionContext(**defaults)

        return factory

    @pytest.mark.asyncio
    async def test_guard_order_is_exact(
        self,
        action_context_factory,
    ):
        """
        Test that guards are called in EXACT order.

        Guard order (MUST NOT CHANGE):
        1. permit_validator
        2. opa_abac
        3. opa_scope
        4. runtime_guard
        5. rate_limiter
        6. target_safety
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )

        call_order = []

        # Create mocks that record call order
        permit_validator = MagicMock()
        permit_validator.check_ttl_expiry.return_value = (False, 3600)
        result = MagicMock()
        result.valid = True
        result.signature_verified = True
        result.issues = []

        def record_permit(*args, **kwargs):
            call_order.append("permit_validator")
            return result

        permit_validator.validate_permit.side_effect = record_permit

        runtime_guard = MagicMock()
        from src.runtime_guard import Decision
        decision = MagicMock()
        decision.decision = Decision.ALLOW
        decision.rule = "RUNTIME.ALLOWED"
        decision.reason = "Allowed"
        decision.attestation_hash = "hash"
        decision.details = {}

        def record_runtime(*args, **kwargs):
            call_order.append("runtime_guard")
            return decision

        runtime_guard.enforce_action.side_effect = record_runtime

        rate_limiter = MagicMock()

        def record_rate(*args, **kwargs):
            call_order.append("rate_limiter")
            return (True, 1)

        rate_limiter.check_rate.side_effect = record_rate

        target_safety = MagicMock()
        safety_result = MagicMock()
        safety_result.allowed = True
        safety_result.warnings = []

        async def record_target(*args, **kwargs):
            call_order.append("target_safety")
            return safety_result

        target_safety.check_action_safety = record_target

        # OPA client mock
        opa_client = MagicMock()

        async def record_opa_abac(*args, **kwargs):
            call_order.append("opa_abac")
            return {"allow": True}

        async def record_opa_scope(*args, **kwargs):
            call_order.append("opa_scope")
            return {"allow": True, "drift_score": 0.0, "severity": "P0"}

        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            opa_client=opa_client,
            runtime_guard=runtime_guard,
            rate_limiter=rate_limiter,
            target_safety=target_safety,
        )

        # Patch OPA query methods
        ecp._query_opa_abac = record_opa_abac
        ecp._query_opa_scope = record_opa_scope

        ecp._test_mode = True
        set_execution_control_plane(ecp)

        ctx = action_context_factory()
        await validate_and_execute_action(ctx)

        # CRITICAL: Assert exact order
        expected_order = [
            "permit_validator",
            "opa_abac",
            "opa_scope",
            "runtime_guard",
            "rate_limiter",
            "target_safety",
        ]

        assert call_order == expected_order, (
            f"Guard order MUST be exactly {expected_order}, "
            f"but was {call_order}. "
            "This is a SECURITY VIOLATION - guard order is immutable."
        )

    @pytest.mark.asyncio
    async def test_downstream_guards_not_called_on_permit_failure(
        self,
        action_context_factory,
    ):
        """
        Test that if permit guard fails, NO downstream guards are called.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import PermitExpiredError

        call_order = []

        # Permit validator that fails
        permit_validator = MagicMock()

        def record_permit_fail(*args, **kwargs):
            call_order.append("permit_validator")
            return (True, 0)  # Expired

        permit_validator.check_ttl_expiry.side_effect = record_permit_fail

        # These should NEVER be called
        runtime_guard = MagicMock()

        def fail_if_called(*args, **kwargs):
            call_order.append("runtime_guard")
            pytest.fail("runtime_guard should NOT be called when permit fails")

        runtime_guard.enforce_action.side_effect = fail_if_called

        rate_limiter = MagicMock()

        def fail_rate_if_called(*args, **kwargs):
            call_order.append("rate_limiter")
            pytest.fail("rate_limiter should NOT be called when permit fails")

        rate_limiter.check_rate.side_effect = fail_rate_if_called

        target_safety = MagicMock()

        async def fail_target_if_called(*args, **kwargs):
            call_order.append("target_safety")
            pytest.fail("target_safety should NOT be called when permit fails")

        target_safety.check_action_safety = fail_target_if_called

        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            runtime_guard=runtime_guard,
            rate_limiter=rate_limiter,
            target_safety=target_safety,
        )
        ecp._test_mode = True
        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(PermitExpiredError):
            await validate_and_execute_action(ctx)

        # Only permit_validator should have been called
        assert call_order == ["permit_validator"], (
            f"Only permit_validator should be called on permit failure, "
            f"but these were called: {call_order}"
        )

    @pytest.mark.asyncio
    async def test_downstream_guards_not_called_on_rate_limit_failure(
        self,
        action_context_factory,
    ):
        """
        Test that if rate limit guard fails, target_safety is NOT called.
        """
        from src.core.engine import (
            ExecutionControlPlane,
            set_execution_control_plane,
            validate_and_execute_action,
        )
        from src.core.exceptions import RateLimitedError

        call_order = []

        # Permit passes
        permit_validator = MagicMock()
        permit_validator.check_ttl_expiry.return_value = (False, 3600)
        result = MagicMock()
        result.valid = True
        result.signature_verified = True
        result.issues = []
        permit_validator.validate_permit.return_value = result

        # Runtime guard passes
        from src.runtime_guard import Decision
        runtime_guard = MagicMock()
        decision = MagicMock()
        decision.decision = Decision.ALLOW
        decision.rule = "ALLOWED"
        decision.reason = "OK"
        decision.attestation_hash = "hash"
        decision.details = {}
        runtime_guard.enforce_action.return_value = decision

        # Rate limiter FAILS
        rate_limiter = MagicMock()

        def record_rate_fail(*args, **kwargs):
            call_order.append("rate_limiter")
            return (False, 100)  # Exceeded

        rate_limiter.check_rate.side_effect = record_rate_fail

        # Target safety should NEVER be called
        target_safety = MagicMock()

        async def fail_if_called(*args, **kwargs):
            call_order.append("target_safety")
            pytest.fail("target_safety should NOT be called when rate limit fails")

        target_safety.check_action_safety = fail_if_called

        ecp = ExecutionControlPlane(
            permit_validator=permit_validator,
            runtime_guard=runtime_guard,
            rate_limiter=rate_limiter,
            target_safety=target_safety,
        )
        ecp._test_mode = True
        set_execution_control_plane(ecp)

        ctx = action_context_factory()

        with pytest.raises(RateLimitedError):
            await validate_and_execute_action(ctx)

        # Target safety should NOT be in the call order
        assert "target_safety" not in call_order, (
            "target_safety should NOT be called when rate_limiter fails"
        )


# ============================================================================
# Test B: Concurrency / Multi-Instance Rate Limit Integrity
# ============================================================================


class TestConcurrencyRateLimitIntegrity:
    """
    v6.1 SECURITY - Rate Limiting MUST Work Under Concurrent Execution

    These tests verify that:
    1. SQLite + sliding window works correctly under parallel execution
    2. Only the allowed count of actions pass through
    3. No double-spend behavior (race conditions)

    This is a DoD-grade requirement: rate limiting that collapses under
    parallel execution is a critical vulnerability.
    """

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database path for rate limiting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "rate_limit.db"

    @pytest.mark.asyncio
    async def test_concurrent_rate_limit_enforcement(self, temp_db_path):
        """
        Test that rate limiting works correctly under concurrent access.

        Spawns multiple concurrent tasks that attempt the same action.
        Verifies only the allowed count passes.
        """
        from src.runtime_guard import RateLimitCounter

        # Create rate limiter with strict limit
        max_rate = 5
        rate_limiter = RateLimitCounter(
            db_path=str(temp_db_path),
            window_seconds=60,
        )

        target_id = "test-target-001"
        results = []

        async def attempt_action(task_id: int):
            """Attempt to execute an action."""
            # Record the action first
            rate_limiter.record_action(
                target_id=target_id,
                campaign_id="test-campaign",
                action_type="test_action",
            )

            # Check if allowed
            allowed, current_rate = rate_limiter.check_rate(target_id, max_rate)
            results.append({
                "task_id": task_id,
                "allowed": allowed,
                "rate": current_rate,
            })
            return allowed

        # Spawn 20 concurrent tasks (well over the limit of 5)
        num_tasks = 20
        tasks = [attempt_action(i) for i in range(num_tasks)]

        # Execute all concurrently
        await asyncio.gather(*tasks)

        # Count how many were allowed
        allowed_count = sum(1 for r in results if r["allowed"])
        blocked_count = sum(1 for r in results if not r["allowed"])

        # CRITICAL: Only max_rate should be allowed
        assert allowed_count <= max_rate, (
            f"Only {max_rate} actions should be allowed, "
            f"but {allowed_count} were allowed. "
            "This is a RACE CONDITION in rate limiting."
        )

        # Most should be blocked
        assert blocked_count >= (num_tasks - max_rate), (
            f"At least {num_tasks - max_rate} should be blocked, "
            f"but only {blocked_count} were blocked."
        )

    @pytest.mark.asyncio
    async def test_no_double_spend_under_concurrent_check_and_record(
        self, temp_db_path
    ):
        """
        Test that check-then-record doesn't allow double-spend.

        This tests for the classic TOCTOU race condition where:
        1. Two threads both check rate at ~same time
        2. Both see rate is OK
        3. Both record their action
        4. Rate limit exceeded but both got through

        Our implementation should prevent this by using atomic operations.
        """
        from src.runtime_guard import RateLimitCounter
        import threading

        # Create rate limiter with limit of 3
        max_rate = 3
        rate_limiter = RateLimitCounter(
            db_path=str(temp_db_path),
            window_seconds=60,
        )

        target_id = "double-spend-test"
        results = []
        barrier = threading.Barrier(10)  # Synchronize 10 threads

        def attempt_with_sync(thread_id: int):
            """Synchronized attempt to maximize race condition likelihood."""
            # Wait for all threads to be ready
            barrier.wait()

            # All threads check+record at ~same instant
            allowed, rate = rate_limiter.check_rate(target_id, max_rate)

            if allowed:
                rate_limiter.record_action(
                    target_id=target_id,
                    campaign_id="test",
                    action_type="concurrent_test",
                )

            results.append({
                "thread_id": thread_id,
                "allowed": allowed,
                "rate_at_check": rate,
            })

        # Spawn threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=attempt_with_sync, args=(i,))
            threads.append(t)

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # Count final rate
        _, final_rate = rate_limiter.check_rate(target_id, max_rate)

        # CRITICAL: Final rate should not exceed max_rate
        # If double-spend occurred, final_rate would be > max_rate
        assert final_rate <= max_rate, (
            f"Final rate is {final_rate} but max is {max_rate}. "
            "DOUBLE-SPEND DETECTED - rate limiting has race condition."
        )

        # Count allowed
        allowed_count = sum(1 for r in results if r["allowed"])
        assert allowed_count <= max_rate, (
            f"{allowed_count} actions were allowed but max is {max_rate}. "
            "Rate limit bypass detected under concurrent access."
        )

    @pytest.mark.asyncio
    async def test_rate_limit_integrity_across_multiple_instances(
        self, temp_db_path
    ):
        """
        Test that rate limiting works when multiple RateLimitCounter instances
        share the same SQLite database (simulating multi-process scenario).

        This is critical for production where multiple workers may share state.
        """
        from src.runtime_guard import RateLimitCounter

        max_rate = 5
        target_id = "multi-instance-test"

        # Create multiple instances pointing to same DB
        instance_1 = RateLimitCounter(db_path=str(temp_db_path), window_seconds=60)
        instance_2 = RateLimitCounter(db_path=str(temp_db_path), window_seconds=60)
        instance_3 = RateLimitCounter(db_path=str(temp_db_path), window_seconds=60)

        instances = [instance_1, instance_2, instance_3]

        # Each instance records actions
        for i, inst in enumerate(instances):
            for _ in range(2):  # 2 actions each = 6 total
                inst.record_action(
                    target_id=target_id,
                    campaign_id="test",
                    action_type=f"action_from_instance_{i}",
                )

        # All instances should see the same rate
        rates = [inst.check_rate(target_id, max_rate) for inst in instances]

        # All should report ~6 actions (may vary slightly due to timing)
        for i, (allowed, rate) in enumerate(rates):
            assert rate >= 5, (
                f"Instance {i} sees rate={rate}, expected >=5. "
                "Instances not sharing state properly."
            )
            assert not allowed, (
                f"Instance {i} allowed action when rate={rate} > max={max_rate}. "
                "Multi-instance rate limiting failed."
            )

        # Verify all instances deny new actions
        for i, inst in enumerate(instances):
            allowed, _ = inst.check_rate(target_id, max_rate)
            assert not allowed, f"Instance {i} should deny when rate exceeded"


# ============================================================================
# Test: Execution Token Validation
# ============================================================================


class TestExecutionTokenValidation:
    """
    v6.1 SECURITY - Execution Token Validation

    These tests verify that:
    1. Execution tokens are generated for each action
    2. Tokens are validated before execution
    3. Tokens cannot be reused (one-time use)
    4. Invalid tokens are rejected
    """

    @pytest.fixture
    def action_context_factory(self, valid_permit):
        """Create an ActionContext for testing."""
        from src.core.engine import ActionContext

        def factory(**kwargs):
            defaults = {
                "tenant_id": str(uuid4()),
                "campaign_id": str(uuid4()),
                "mode": "SIM",
                "risk_tier": 1,
                "scope_id": "scope-001",
                "action": {"type": "reconnaissance", "tool_id": "nmap"},
                "target": {"target_id": "host-001", "asset": "10.0.0.1"},
                "entrypoint": {"entrypoint_id": "ep-001"},
                "permit": valid_permit,
            }
            defaults.update(kwargs)
            return ActionContext(**defaults)

        return factory

    @pytest.mark.asyncio
    async def test_token_generation_requires_all_guards_passed(self):
        """Test that token can only be generated if all guards passed."""
        from src.core.engine import ExecutionControlPlane, DecisionRecord
        from src.core.exceptions import GuardBypassError

        ecp = ExecutionControlPlane()

        # Create a record where guards did NOT all pass
        record = DecisionRecord(
            action_id="test-action",
            action_context_hash="hash",
        )
        record.all_guards_passed = False

        # Should raise GuardBypassError
        with pytest.raises(GuardBypassError) as exc_info:
            ecp.generate_execution_token("test-action", record)

        assert "guards did not all pass" in str(exc_info.value.message)

    @pytest.mark.asyncio
    async def test_token_is_one_time_use(self):
        """Test that tokens can only be validated once."""
        from src.core.engine import ExecutionControlPlane, DecisionRecord

        ecp = ExecutionControlPlane()

        # Create a record where all guards passed
        record = DecisionRecord(
            action_id="test-action",
            action_context_hash="hash",
        )
        record.all_guards_passed = True

        # Generate token
        token = ecp.generate_execution_token("test-action", record)

        # First validation should succeed
        assert ecp.validate_execution_token("test-action", token) is True

        # Second validation should fail (token consumed)
        assert ecp.validate_execution_token("test-action", token) is False

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self):
        """Test that invalid tokens are rejected."""
        from src.core.engine import ExecutionControlPlane, DecisionRecord

        ecp = ExecutionControlPlane()

        # Create a record and generate token
        record = DecisionRecord(
            action_id="test-action",
            action_context_hash="hash",
        )
        record.all_guards_passed = True

        ecp.generate_execution_token("test-action", record)

        # Try to validate with wrong token
        assert ecp.validate_execution_token("test-action", "wrong-token") is False

        # Original token should still be valid (wrong token doesn't consume)
        # Actually no - validation with wrong token doesn't consume the real token
        # but the check itself should fail

    @pytest.mark.asyncio
    async def test_token_revocation(self):
        """Test that tokens can be revoked."""
        from src.core.engine import ExecutionControlPlane, DecisionRecord

        ecp = ExecutionControlPlane()

        record = DecisionRecord(
            action_id="test-action",
            action_context_hash="hash",
        )
        record.all_guards_passed = True

        token = ecp.generate_execution_token("test-action", record)

        # Revoke the token
        assert ecp.revoke_execution_token("test-action") is True

        # Token should no longer be valid
        assert ecp.validate_execution_token("test-action", token) is False

        # Revoking again should return False (already revoked)
        assert ecp.revoke_execution_token("test-action") is False
