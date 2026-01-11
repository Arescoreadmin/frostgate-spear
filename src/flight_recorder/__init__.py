"""
Flight Recorder CLI - Blueprint v6.1 §0

Streams append-only ledger with verification for WTF Operator Experience.
`fgs watch <campaign>` streams append-only ledger with verification.
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Callable, Optional
from uuid import uuid4


class EventType(Enum):
    """Types of events in the flight recorder ledger."""
    CAMPAIGN_STARTED = "CAMPAIGN_STARTED"
    CAMPAIGN_PAUSED = "CAMPAIGN_PAUSED"
    CAMPAIGN_RESUMED = "CAMPAIGN_RESUMED"
    CAMPAIGN_COMPLETED = "CAMPAIGN_COMPLETED"
    CAMPAIGN_ABORTED = "CAMPAIGN_ABORTED"
    ACTION_PLANNED = "ACTION_PLANNED"
    ACTION_APPROVED = "ACTION_APPROVED"
    ACTION_DENIED = "ACTION_DENIED"
    ACTION_STARTED = "ACTION_STARTED"
    ACTION_COMPLETED = "ACTION_COMPLETED"
    ACTION_FAILED = "ACTION_FAILED"
    TOOL_INVOKED = "TOOL_INVOKED"
    TOOL_RESULT = "TOOL_RESULT"
    FINDING_DISCOVERED = "FINDING_DISCOVERED"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    BUDGET_WARNING = "BUDGET_WARNING"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    SCOPE_VIOLATION_DETECTED = "SCOPE_VIOLATION_DETECTED"
    REVOCATION_RECEIVED = "REVOCATION_RECEIVED"
    CHECKPOINT_CREATED = "CHECKPOINT_CREATED"
    WITNESS_ATTESTATION = "WITNESS_ATTESTATION"


class VerificationStatus(Enum):
    """Status of ledger entry verification."""
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INVALID = "INVALID"
    PENDING = "PENDING"


@dataclass
class LedgerEntry:
    """A single entry in the append-only ledger."""
    entry_id: str
    campaign_id: str
    sequence_number: int
    event_type: EventType
    timestamp: datetime
    payload: dict
    previous_hash: Optional[str]
    entry_hash: str
    signature: Optional[str] = None
    witness_signature: Optional[str] = None
    verification_status: VerificationStatus = VerificationStatus.PENDING


@dataclass
class LedgerStats:
    """Statistics for the ledger."""
    total_entries: int
    verified_entries: int
    invalid_entries: int
    last_sequence: int
    first_timestamp: Optional[datetime]
    last_timestamp: Optional[datetime]
    chain_intact: bool


@dataclass
class WatchFilter:
    """Filter configuration for watch command."""
    event_types: Optional[list[EventType]] = None
    min_severity: Optional[str] = None
    include_evidence: bool = False
    include_policy_details: bool = True
    include_cost: bool = True


class AppendOnlyLedger:
    """
    Append-only ledger for campaign events.

    Per Blueprint v6.1 §0:
    - Flight Recorder CLI streams append-only ledger with verification
    """

    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        self._entries: list[LedgerEntry] = []
        self._sequence_counter = 0
        self._subscribers: list[Callable[[LedgerEntry], None]] = []

    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def append(
        self,
        event_type: EventType,
        payload: dict,
        signature: Optional[str] = None,
    ) -> LedgerEntry:
        """Append a new entry to the ledger."""
        self._sequence_counter += 1

        previous_hash = None
        if self._entries:
            previous_hash = self._entries[-1].entry_hash

        entry_id = f"entry-{uuid4().hex[:16]}"
        timestamp = datetime.now(timezone.utc)

        # Compute entry hash
        hash_content = {
            'entry_id': entry_id,
            'campaign_id': self.campaign_id,
            'sequence_number': self._sequence_counter,
            'event_type': event_type.value,
            'timestamp': timestamp.isoformat(),
            'payload_hash': self._compute_hash(payload),
            'previous_hash': previous_hash
        }
        entry_hash = self._compute_hash(hash_content)

        entry = LedgerEntry(
            entry_id=entry_id,
            campaign_id=self.campaign_id,
            sequence_number=self._sequence_counter,
            event_type=event_type,
            timestamp=timestamp,
            payload=payload,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            signature=signature
        )

        self._entries.append(entry)

        # Notify subscribers
        for subscriber in self._subscribers:
            try:
                subscriber(entry)
            except Exception:
                pass

        return entry

    def subscribe(self, callback: Callable[[LedgerEntry], None]) -> None:
        """Subscribe to new ledger entries."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[LedgerEntry], None]) -> None:
        """Unsubscribe from ledger entries."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the entire ledger chain."""
        issues = []

        if not self._entries:
            return True, []

        # Verify first entry has no previous hash
        if self._entries[0].previous_hash is not None:
            issues.append("First entry should have no previous hash")

        # Verify sequence and chain
        for i, entry in enumerate(self._entries):
            # Check sequence
            if entry.sequence_number != i + 1:
                issues.append(f"Sequence gap at entry {entry.entry_id}")

            # Check chain link
            if i > 0:
                expected_prev = self._entries[i - 1].entry_hash
                if entry.previous_hash != expected_prev:
                    issues.append(f"Chain break at entry {entry.entry_id}")

            # Verify entry hash
            hash_content = {
                'entry_id': entry.entry_id,
                'campaign_id': entry.campaign_id,
                'sequence_number': entry.sequence_number,
                'event_type': entry.event_type.value,
                'timestamp': entry.timestamp.isoformat(),
                'payload_hash': self._compute_hash(entry.payload),
                'previous_hash': entry.previous_hash
            }
            expected_hash = self._compute_hash(hash_content)
            if entry.entry_hash != expected_hash:
                issues.append(f"Hash mismatch at entry {entry.entry_id}")
                entry.verification_status = VerificationStatus.INVALID
            else:
                entry.verification_status = VerificationStatus.VERIFIED

        return len(issues) == 0, issues

    def get_stats(self) -> LedgerStats:
        """Get ledger statistics."""
        verified = sum(1 for e in self._entries if e.verification_status == VerificationStatus.VERIFIED)
        invalid = sum(1 for e in self._entries if e.verification_status == VerificationStatus.INVALID)
        chain_intact, _ = self.verify_chain()

        return LedgerStats(
            total_entries=len(self._entries),
            verified_entries=verified,
            invalid_entries=invalid,
            last_sequence=self._sequence_counter,
            first_timestamp=self._entries[0].timestamp if self._entries else None,
            last_timestamp=self._entries[-1].timestamp if self._entries else None,
            chain_intact=chain_intact
        )

    def get_entries(
        self,
        start_sequence: int = 0,
        limit: Optional[int] = None,
        event_types: Optional[list[EventType]] = None,
    ) -> list[LedgerEntry]:
        """Get ledger entries with optional filtering."""
        entries = [e for e in self._entries if e.sequence_number > start_sequence]

        if event_types:
            entries = [e for e in entries if e.event_type in event_types]

        if limit:
            entries = entries[:limit]

        return entries

    def export_json(self) -> str:
        """Export ledger as JSON."""
        return json.dumps({
            'campaign_id': self.campaign_id,
            'entries': [
                {
                    'entry_id': e.entry_id,
                    'sequence_number': e.sequence_number,
                    'event_type': e.event_type.value,
                    'timestamp': e.timestamp.isoformat(),
                    'payload': e.payload,
                    'previous_hash': e.previous_hash,
                    'entry_hash': e.entry_hash,
                    'verification_status': e.verification_status.value
                }
                for e in self._entries
            ],
            'stats': {
                'total_entries': len(self._entries),
                'last_sequence': self._sequence_counter
            }
        }, indent=2)


class FlightRecorder:
    """
    Flight Recorder for campaign monitoring.

    Per Blueprint v6.1 §0 (WTF Operator Experience):
    - `fgs watch <campaign>` streams append-only ledger with verification
    """

    def __init__(self):
        self._ledgers: dict[str, AppendOnlyLedger] = {}
        self._active_watches: dict[str, asyncio.Task] = {}

    def get_or_create_ledger(self, campaign_id: str) -> AppendOnlyLedger:
        """Get or create a ledger for a campaign."""
        if campaign_id not in self._ledgers:
            self._ledgers[campaign_id] = AppendOnlyLedger(campaign_id)
        return self._ledgers[campaign_id]

    def record_event(
        self,
        campaign_id: str,
        event_type: EventType,
        payload: dict,
        signature: Optional[str] = None,
    ) -> LedgerEntry:
        """Record an event to the flight recorder."""
        ledger = self.get_or_create_ledger(campaign_id)
        return ledger.append(event_type, payload, signature)

    async def watch(
        self,
        campaign_id: str,
        filter_config: Optional[WatchFilter] = None,
        output_callback: Optional[Callable[[LedgerEntry], None]] = None,
    ) -> AsyncIterator[LedgerEntry]:
        """
        Watch a campaign's ledger in real-time.

        Implements `fgs watch <campaign>` per Blueprint v6.1 §0.
        """
        ledger = self.get_or_create_ledger(campaign_id)
        filter_config = filter_config or WatchFilter()

        last_seen = 0
        queue: asyncio.Queue[LedgerEntry] = asyncio.Queue()

        def on_entry(entry: LedgerEntry):
            if filter_config.event_types and entry.event_type not in filter_config.event_types:
                return
            queue.put_nowait(entry)
            if output_callback:
                output_callback(entry)

        ledger.subscribe(on_entry)

        try:
            # First, yield existing entries
            for entry in ledger.get_entries(event_types=filter_config.event_types):
                if entry.sequence_number > last_seen:
                    last_seen = entry.sequence_number
                    yield entry

            # Then stream new entries
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=1.0)
                    if entry.sequence_number > last_seen:
                        last_seen = entry.sequence_number
                        yield entry
                except asyncio.TimeoutError:
                    # Check if campaign is still active
                    continue
        finally:
            ledger.unsubscribe(on_entry)

    def format_entry(self, entry: LedgerEntry, verbose: bool = False) -> str:
        """Format a ledger entry for display."""
        timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        status_icon = {
            VerificationStatus.VERIFIED: "✓",
            VerificationStatus.UNVERIFIED: "?",
            VerificationStatus.INVALID: "✗",
            VerificationStatus.PENDING: "○"
        }.get(entry.verification_status, "?")

        event_icon = {
            EventType.CAMPAIGN_STARTED: "▶",
            EventType.CAMPAIGN_COMPLETED: "■",
            EventType.CAMPAIGN_ABORTED: "⊘",
            EventType.ACTION_STARTED: "→",
            EventType.ACTION_COMPLETED: "✓",
            EventType.ACTION_FAILED: "✗",
            EventType.FINDING_DISCOVERED: "!",
            EventType.POLICY_EVALUATED: "⚖",
            EventType.BUDGET_WARNING: "⚠",
            EventType.SCOPE_VIOLATION_DETECTED: "⛔"
        }.get(entry.event_type, "•")

        base = f"[{timestamp}] {status_icon} {entry.sequence_number:04d} {event_icon} {entry.event_type.value}"

        if verbose:
            base += f"\n  Entry ID: {entry.entry_id}"
            base += f"\n  Hash: {entry.entry_hash}"
            if entry.previous_hash:
                base += f"\n  Prev: {entry.previous_hash}"
            base += f"\n  Payload: {json.dumps(entry.payload, indent=4)}"

        return base

    def verify_campaign(self, campaign_id: str) -> dict:
        """Verify integrity of a campaign's ledger."""
        if campaign_id not in self._ledgers:
            return {'error': 'Campaign not found', 'valid': False}

        ledger = self._ledgers[campaign_id]
        is_valid, issues = ledger.verify_chain()
        stats = ledger.get_stats()

        return {
            'campaign_id': campaign_id,
            'valid': is_valid,
            'issues': issues,
            'stats': {
                'total_entries': stats.total_entries,
                'verified_entries': stats.verified_entries,
                'invalid_entries': stats.invalid_entries,
                'chain_intact': stats.chain_intact,
                'first_timestamp': stats.first_timestamp.isoformat() if stats.first_timestamp else None,
                'last_timestamp': stats.last_timestamp.isoformat() if stats.last_timestamp else None
            }
        }

    def export_ledger(self, campaign_id: str) -> Optional[str]:
        """Export a campaign's ledger as JSON."""
        if campaign_id not in self._ledgers:
            return None
        return self._ledgers[campaign_id].export_json()

    def get_summary(self, campaign_id: str) -> dict:
        """Get summary of campaign events."""
        if campaign_id not in self._ledgers:
            return {'error': 'Campaign not found'}

        ledger = self._ledgers[campaign_id]
        entries = ledger.get_entries()

        by_type: dict[str, int] = {}
        for entry in entries:
            by_type[entry.event_type.value] = by_type.get(entry.event_type.value, 0) + 1

        findings = [e for e in entries if e.event_type == EventType.FINDING_DISCOVERED]
        actions = [e for e in entries if e.event_type in (
            EventType.ACTION_STARTED, EventType.ACTION_COMPLETED, EventType.ACTION_FAILED
        )]

        return {
            'campaign_id': campaign_id,
            'total_events': len(entries),
            'by_type': by_type,
            'findings_count': len(findings),
            'actions_count': len(actions),
            'action_success_rate': (
                sum(1 for a in actions if a.event_type == EventType.ACTION_COMPLETED) / len(actions)
                if actions else 0
            )
        }


# CLI-style interface functions
def format_watch_output(entry: LedgerEntry) -> str:
    """Format entry for CLI watch output."""
    recorder = FlightRecorder()
    return recorder.format_entry(entry, verbose=False)


def create_watch_stream(
    campaign_id: str,
    recorder: FlightRecorder,
    filter_config: Optional[WatchFilter] = None,
) -> AsyncIterator[str]:
    """Create a formatted watch stream for CLI."""
    async def stream():
        async for entry in recorder.watch(campaign_id, filter_config):
            yield format_watch_output(entry)
    return stream()
