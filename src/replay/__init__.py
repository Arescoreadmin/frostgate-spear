"""
Replay Service - Blueprint v6.1 §0, §3.1, §9

Deterministic replay runner with manifests for reproducible execution.
Implements the Replay Debugger for WTF Operator Experience.
"""

import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from uuid import uuid4


class ReplayStatus(Enum):
    """Status of a replay execution."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    VARIANCE_DETECTED = "VARIANCE_DETECTED"


class SeedStrategy(Enum):
    """RNG seed strategies per Blueprint v6.1 §9."""
    FIXED_SEED = "FIXED_SEED"
    RECORDED_SEED = "RECORDED_SEED"
    DERIVED_FROM_CAMPAIGN = "DERIVED_FROM_CAMPAIGN"


class TimeStrategy(Enum):
    """Time virtualization strategies."""
    RECORDED_TIMESTAMPS = "RECORDED_TIMESTAMPS"
    SIMULATED_CLOCK = "SIMULATED_CLOCK"
    DETERMINISTIC_ADVANCE = "DETERMINISTIC_ADVANCE"


class OrderingStrategy(Enum):
    """Event ordering strategies."""
    STRICT_SEQUENTIAL = "STRICT_SEQUENTIAL"
    CAUSAL_ORDERING = "CAUSAL_ORDERING"
    PARTIAL_ORDER_WITH_BARRIERS = "PARTIAL_ORDER_WITH_BARRIERS"


class BreakpointType(Enum):
    """Types of breakpoints for Replay Debugger."""
    EVENT = "EVENT"
    ACTION = "ACTION"
    VARIANCE_DETECTED = "VARIANCE_DETECTED"
    POLICY_DECISION = "POLICY_DECISION"


@dataclass
class DeterminismConfig:
    """
    Determinism configuration per Blueprint v6.1 §9.

    Required:
    - Deterministic RNG seeding
    - Time virtualization
    - Ordering guarantees
    """
    rng_enabled: bool = True
    rng_seed_strategy: SeedStrategy = SeedStrategy.RECORDED_SEED
    master_seed: Optional[str] = None
    per_component_seeds: dict[str, str] = field(default_factory=dict)

    time_virtualization_enabled: bool = True
    time_strategy: TimeStrategy = TimeStrategy.RECORDED_TIMESTAMPS
    epoch_start: Optional[datetime] = None
    time_scale_factor: float = 1.0

    network_mocking_enabled: bool = True
    mock_strategy: str = "RECORDED_RESPONSES"
    response_cache_ref: Optional[str] = None


@dataclass
class SnapshotRef:
    """Reference to a snapshot for replay."""
    snapshot_id: str
    hash: str
    snapshot_type: str  # environment, tool_version, config
    metadata: dict = field(default_factory=dict)


@dataclass
class NondeterministicInput:
    """Captured nondeterministic input for replay."""
    input_id: str
    input_type: str
    sequence_number: int
    timestamp: datetime
    hash: str
    storage_ref: str
    associated_action_id: Optional[str] = None
    _value: Any = field(default=None, repr=False)


@dataclass
class ReplayCheckpoint:
    """Checkpoint during replay execution."""
    checkpoint_id: str
    at_event: int
    state_hash: str
    timestamp: datetime


@dataclass
class Breakpoint:
    """Debugger breakpoint configuration."""
    breakpoint_id: str
    breakpoint_type: BreakpointType
    condition: Optional[str] = None
    enabled: bool = True


@dataclass
class VarianceReport:
    """Report of variance between original and replay."""
    variance_id: str
    event_index: int
    variance_type: str
    original_value_hash: str
    replay_value_hash: str
    severity: str  # INFO, WARNING, ERROR
    root_cause: Optional[str] = None


@dataclass
class ReplayManifest:
    """
    Replay manifest per Blueprint v6.1 §4.2.7.

    Contains all information needed for deterministic replay.
    """
    protocol_id: str
    version: str
    campaign_id: str
    original_execution_id: str
    determinism_config: DeterminismConfig
    snapshot_refs: dict[str, list[SnapshotRef]]
    nondeterministic_inputs: list[NondeterministicInput]
    ordering_strategy: OrderingStrategy
    event_ordering: list[dict]
    total_events: int
    total_actions: int
    expected_duration_ms: int
    checkpoints: list[ReplayCheckpoint]
    variance_tolerance: dict


@dataclass
class ReplaySession:
    """An active replay session."""
    session_id: str
    manifest: ReplayManifest
    status: ReplayStatus
    current_event_index: int
    variances: list[VarianceReport]
    breakpoints: list[Breakpoint]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    paused_at_event: Optional[int] = None


class DeterministicRNG:
    """Deterministic random number generator for replay."""

    def __init__(self, seed: str):
        self._seed = seed
        self._state = int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16)

    def random(self) -> float:
        """Generate deterministic random float [0, 1)."""
        self._state = (self._state * 1103515245 + 12345) & 0x7fffffff
        return self._state / 0x7fffffff

    def randint(self, a: int, b: int) -> int:
        """Generate deterministic random integer in [a, b]."""
        return a + int(self.random() * (b - a + 1))

    def choice(self, seq: list) -> Any:
        """Deterministic choice from sequence."""
        return seq[self.randint(0, len(seq) - 1)]


class VirtualClock:
    """Virtual clock for time virtualization."""

    def __init__(
        self,
        strategy: TimeStrategy,
        epoch_start: Optional[datetime] = None,
        scale_factor: float = 1.0,
    ):
        self.strategy = strategy
        self.epoch_start = epoch_start or datetime.now(timezone.utc)
        self.scale_factor = scale_factor
        self._recorded_times: list[datetime] = []
        self._current_index = 0
        self._virtual_offset = 0.0

    def set_recorded_times(self, times: list[datetime]) -> None:
        """Set recorded timestamps for replay."""
        self._recorded_times = times
        self._current_index = 0

    def now(self) -> datetime:
        """Get current virtual time."""
        if self.strategy == TimeStrategy.RECORDED_TIMESTAMPS:
            if self._current_index < len(self._recorded_times):
                t = self._recorded_times[self._current_index]
                self._current_index += 1
                return t
            return datetime.now(timezone.utc)

        elif self.strategy == TimeStrategy.SIMULATED_CLOCK:
            elapsed = (datetime.now(timezone.utc) - self.epoch_start).total_seconds()
            scaled_elapsed = elapsed * self.scale_factor
            return datetime.fromtimestamp(
                self.epoch_start.timestamp() + scaled_elapsed,
                tz=timezone.utc
            )

        elif self.strategy == TimeStrategy.DETERMINISTIC_ADVANCE:
            virtual_time = datetime.fromtimestamp(
                self.epoch_start.timestamp() + self._virtual_offset,
                tz=timezone.utc
            )
            self._virtual_offset += 1.0  # Advance by 1 second each call
            return virtual_time

        return datetime.now(timezone.utc)


class ReplayService:
    """
    Replay Service per Blueprint v6.1 §3.1, §9.

    Per Blueprint v6.1 §0 (WTF Operator Experience):
    - Replay Debugger (deterministic step-through + diff vs original + post-fix retest diff)

    Per Blueprint v6.1 §9 (Determinism Protocol - Final Boss Mandatory):
    - Deterministic RNG seeding
    - Time virtualization
    - Ordering guarantees
    - Snapshot refs for env/tool versions/configs
    - Capture nondeterministic inputs with hashes
    """

    def __init__(self, service_id: str):
        self.service_id = service_id
        self._manifests: dict[str, ReplayManifest] = {}
        self._sessions: dict[str, ReplaySession] = {}
        self._execution_history: dict[str, list[dict]] = {}  # execution_id -> events

    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def record_execution(
        self,
        execution_id: str,
        campaign_id: str,
        events: list[dict],
        tool_versions: dict[str, str],
        config_hashes: dict[str, str],
    ) -> ReplayManifest:
        """
        Record an execution for future replay.

        Captures:
        - All events with ordering
        - Nondeterministic inputs
        - Environment/tool snapshots
        """
        self._execution_history[execution_id] = events

        # Generate master seed from execution
        master_seed = self._compute_hash({
            'execution_id': execution_id,
            'campaign_id': campaign_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

        # Capture nondeterministic inputs
        nondeterministic_inputs = []
        for i, event in enumerate(events):
            if event.get('has_external_input'):
                ndi = NondeterministicInput(
                    input_id=f"ndi-{uuid4().hex[:12]}",
                    input_type=event.get('input_type', 'UNKNOWN'),
                    sequence_number=i,
                    timestamp=datetime.fromisoformat(event.get('timestamp', datetime.now(timezone.utc).isoformat())),
                    hash=self._compute_hash(event.get('external_input', {})),
                    storage_ref=f"storage://inputs/{execution_id}/{i}",
                    associated_action_id=event.get('action_id'),
                    _value=event.get('external_input')
                )
                nondeterministic_inputs.append(ndi)

        # Create snapshot refs
        env_snapshot = SnapshotRef(
            snapshot_id=f"env-{uuid4().hex[:8]}",
            hash=self._compute_hash({'execution_id': execution_id}),
            snapshot_type='environment'
        )

        tool_snapshots = [
            SnapshotRef(
                snapshot_id=f"tool-{tool_id}",
                hash=self._compute_hash(version),
                snapshot_type='tool_version',
                metadata={'tool_id': tool_id, 'version': version}
            )
            for tool_id, version in tool_versions.items()
        ]

        config_snapshots = [
            SnapshotRef(
                snapshot_id=f"config-{name}",
                hash=hash_val,
                snapshot_type='config',
                metadata={'config_name': name}
            )
            for name, hash_val in config_hashes.items()
        ]

        # Create event ordering
        event_ordering = [
            {
                'event_id': event.get('event_id', f"event-{i}"),
                'sequence': i,
                'depends_on': event.get('depends_on', [])
            }
            for i, event in enumerate(events)
        ]

        # Create checkpoints
        checkpoints = []
        checkpoint_interval = max(1, len(events) // 10)  # ~10 checkpoints
        for i in range(0, len(events), checkpoint_interval):
            checkpoints.append(ReplayCheckpoint(
                checkpoint_id=f"ckpt-{i}",
                at_event=i,
                state_hash=self._compute_hash(events[:i+1]),
                timestamp=datetime.now(timezone.utc)
            ))

        manifest = ReplayManifest(
            protocol_id=f"replay-{uuid4().hex[:16]}",
            version="1.0.0",
            campaign_id=campaign_id,
            original_execution_id=execution_id,
            determinism_config=DeterminismConfig(
                master_seed=master_seed,
                epoch_start=datetime.now(timezone.utc)
            ),
            snapshot_refs={
                'environment': [env_snapshot],
                'tool_versions': tool_snapshots,
                'configs': config_snapshots
            },
            nondeterministic_inputs=nondeterministic_inputs,
            ordering_strategy=OrderingStrategy.STRICT_SEQUENTIAL,
            event_ordering=event_ordering,
            total_events=len(events),
            total_actions=sum(1 for e in events if e.get('type') == 'action'),
            expected_duration_ms=sum(e.get('duration_ms', 0) for e in events),
            checkpoints=checkpoints,
            variance_tolerance={
                'timing_variance_ms': 100,
                'output_diff_threshold': 0.01,
                'strict_mode': True
            }
        )

        self._manifests[manifest.protocol_id] = manifest
        return manifest

    def start_replay(
        self,
        manifest_id: str,
        breakpoints: Optional[list[Breakpoint]] = None,
    ) -> Optional[ReplaySession]:
        """Start a new replay session."""
        if manifest_id not in self._manifests:
            return None

        manifest = self._manifests[manifest_id]

        session = ReplaySession(
            session_id=f"session-{uuid4().hex[:12]}",
            manifest=manifest,
            status=ReplayStatus.RUNNING,
            current_event_index=0,
            variances=[],
            breakpoints=breakpoints or [],
            started_at=datetime.now(timezone.utc)
        )

        self._sessions[session.session_id] = session
        return session

    def step(self, session_id: str) -> Optional[dict]:
        """
        Execute single step in replay (step-through debugging).

        Per Blueprint v6.1 §0:
        - Replay Debugger supports deterministic step-through
        """
        if session_id not in self._sessions:
            return None

        session = self._sessions[session_id]
        if session.status not in (ReplayStatus.RUNNING, ReplayStatus.PAUSED):
            return {'error': 'Session not in runnable state'}

        manifest = session.manifest
        if session.current_event_index >= manifest.total_events:
            session.status = ReplayStatus.COMPLETED
            session.completed_at = datetime.now(timezone.utc)
            return {'status': 'completed'}

        # Get original event
        original_events = self._execution_history.get(manifest.original_execution_id, [])
        if session.current_event_index >= len(original_events):
            return {'error': 'Event index out of bounds'}

        original_event = original_events[session.current_event_index]

        # Check breakpoints
        for bp in session.breakpoints:
            if not bp.enabled:
                continue
            if bp.breakpoint_type == BreakpointType.EVENT:
                session.status = ReplayStatus.PAUSED
                session.paused_at_event = session.current_event_index
                return {
                    'status': 'breakpoint_hit',
                    'breakpoint': bp.breakpoint_id,
                    'event_index': session.current_event_index
                }

        # Execute replay step (simulate)
        replay_result = self._execute_replay_step(session, original_event)

        # Check for variance
        if replay_result.get('variance_detected'):
            variance = VarianceReport(
                variance_id=f"var-{uuid4().hex[:12]}",
                event_index=session.current_event_index,
                variance_type=replay_result.get('variance_type', 'OUTPUT_MISMATCH'),
                original_value_hash=self._compute_hash(original_event),
                replay_value_hash=self._compute_hash(replay_result.get('replay_event', {})),
                severity=replay_result.get('variance_severity', 'WARNING')
            )
            session.variances.append(variance)

            if manifest.variance_tolerance.get('strict_mode'):
                session.status = ReplayStatus.VARIANCE_DETECTED
                return {
                    'status': 'variance_detected',
                    'variance': variance,
                    'event_index': session.current_event_index
                }

        session.current_event_index += 1
        return {
            'status': 'stepped',
            'event_index': session.current_event_index - 1,
            'event': original_event,
            'replay_result': replay_result
        }

    def _execute_replay_step(self, session: ReplaySession, original_event: dict) -> dict:
        """Execute a single replay step."""
        manifest = session.manifest
        config = manifest.determinism_config

        # Initialize deterministic RNG
        rng = DeterministicRNG(config.master_seed or "default")

        # Initialize virtual clock
        clock = VirtualClock(
            strategy=config.time_strategy,
            epoch_start=config.epoch_start,
            scale_factor=config.time_scale_factor
        )

        # Inject recorded nondeterministic inputs
        ndi_for_event = [
            ndi for ndi in manifest.nondeterministic_inputs
            if ndi.sequence_number == session.current_event_index
        ]

        # Simulate replay execution
        replay_event = original_event.copy()
        replay_event['replay_timestamp'] = clock.now().isoformat()

        # Check for variance (simplified)
        variance_detected = False
        if ndi_for_event:
            # If we have recorded inputs, verify they match
            for ndi in ndi_for_event:
                if ndi.hash != self._compute_hash(original_event.get('external_input', {})):
                    variance_detected = True

        return {
            'replay_event': replay_event,
            'variance_detected': variance_detected,
            'variance_type': 'INPUT_MISMATCH' if variance_detected else None,
            'variance_severity': 'WARNING' if variance_detected else None
        }

    def get_diff(self, session_id: str, event_index: int) -> Optional[dict]:
        """
        Get diff between original and replay at specific event.

        Per Blueprint v6.1 §0:
        - Diff vs original
        """
        if session_id not in self._sessions:
            return None

        session = self._sessions[session_id]
        manifest = session.manifest

        original_events = self._execution_history.get(manifest.original_execution_id, [])
        if event_index >= len(original_events):
            return None

        original = original_events[event_index]

        # Find variance at this index
        variance = next(
            (v for v in session.variances if v.event_index == event_index),
            None
        )

        return {
            'event_index': event_index,
            'original_hash': self._compute_hash(original),
            'has_variance': variance is not None,
            'variance': variance.__dict__ if variance else None
        }

    def pause(self, session_id: str) -> bool:
        """Pause a replay session."""
        if session_id not in self._sessions:
            return False
        session = self._sessions[session_id]
        if session.status == ReplayStatus.RUNNING:
            session.status = ReplayStatus.PAUSED
            session.paused_at_event = session.current_event_index
            return True
        return False

    def resume(self, session_id: str) -> bool:
        """Resume a paused replay session."""
        if session_id not in self._sessions:
            return False
        session = self._sessions[session_id]
        if session.status == ReplayStatus.PAUSED:
            session.status = ReplayStatus.RUNNING
            return True
        return False

    def add_breakpoint(
        self,
        session_id: str,
        breakpoint_type: BreakpointType,
        condition: Optional[str] = None,
    ) -> Optional[str]:
        """Add a breakpoint to a replay session."""
        if session_id not in self._sessions:
            return None
        session = self._sessions[session_id]
        bp = Breakpoint(
            breakpoint_id=f"bp-{uuid4().hex[:8]}",
            breakpoint_type=breakpoint_type,
            condition=condition
        )
        session.breakpoints.append(bp)
        return bp.breakpoint_id

    def get_variance_summary(self, session_id: str) -> dict:
        """Get summary of all variances in a replay session."""
        if session_id not in self._sessions:
            return {}

        session = self._sessions[session_id]
        return {
            'session_id': session_id,
            'total_variances': len(session.variances),
            'by_type': {},
            'by_severity': {
                'INFO': sum(1 for v in session.variances if v.severity == 'INFO'),
                'WARNING': sum(1 for v in session.variances if v.severity == 'WARNING'),
                'ERROR': sum(1 for v in session.variances if v.severity == 'ERROR')
            },
            'root_causes': [v.root_cause for v in session.variances if v.root_cause]
        }

    def export_manifest(self, manifest_id: str) -> Optional[dict]:
        """Export replay manifest as dictionary."""
        if manifest_id not in self._manifests:
            return None

        m = self._manifests[manifest_id]
        return {
            'protocol_id': m.protocol_id,
            'version': m.version,
            'campaign_id': m.campaign_id,
            'original_execution_id': m.original_execution_id,
            'determinism_config': {
                'rng_seeding': {
                    'enabled': m.determinism_config.rng_enabled,
                    'seed_strategy': m.determinism_config.rng_seed_strategy.value,
                    'master_seed': m.determinism_config.master_seed
                },
                'time_virtualization': {
                    'enabled': m.determinism_config.time_virtualization_enabled,
                    'strategy': m.determinism_config.time_strategy.value
                },
                'network_mocking': {
                    'enabled': m.determinism_config.network_mocking_enabled
                }
            },
            'snapshot_refs': {
                category: [
                    {'snapshot_id': s.snapshot_id, 'hash': s.hash}
                    for s in snapshots
                ]
                for category, snapshots in m.snapshot_refs.items()
            },
            'ordering_guarantees': {
                'strategy': m.ordering_strategy.value,
                'event_count': len(m.event_ordering)
            },
            'replay_manifest': {
                'total_events': m.total_events,
                'total_actions': m.total_actions,
                'expected_duration_ms': m.expected_duration_ms,
                'checkpoints': [
                    {'checkpoint_id': c.checkpoint_id, 'at_event': c.at_event}
                    for c in m.checkpoints
                ]
            },
            'variance_tolerance': m.variance_tolerance
        }
