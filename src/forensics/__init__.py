"""
Frost Gate Spear - Forensics Manager

Forensic logging, integrity verification, and replay capabilities.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.exceptions import ForensicIntegrityError

logger = logging.getLogger(__name__)


@dataclass
class ForensicRecord:
    """Single forensic log record."""
    record_id: UUID
    mission_id: UUID
    timestamp: datetime
    event_type: str
    data: Dict[str, Any]
    hash: str
    previous_hash: str
    classification_level: str


@dataclass
class MerkleNode:
    """Node in Merkle tree for integrity verification."""
    hash: str
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None
    data: Optional[str] = None


@dataclass
class ReplayResult:
    """Result of mission replay."""
    mission_id: UUID
    success: bool
    completeness: float
    divergences: List[Dict[str, Any]]
    timestamp: datetime


class ForensicsManager:
    """
    Forensics Manager.

    Provides:
    - WORM (Write Once Read Many) logging
    - External timestamping
    - Merkle tree integrity verification
    - Mission replay capability
    - Forensic completeness scoring
    """

    def __init__(self, config: Config):
        """Initialize Forensics Manager."""
        self.config = config
        self._records: Dict[UUID, List[ForensicRecord]] = {}
        self._merkle_roots: Dict[UUID, str] = {}
        self._last_hash: Dict[UUID, str] = {}

    async def start(self) -> None:
        """Start Forensics Manager."""
        logger.info("Starting Forensics Manager...")
        await self._initialize_storage()
        logger.info("Forensics Manager started")

    async def stop(self) -> None:
        """Stop Forensics Manager."""
        logger.info("Stopping Forensics Manager...")
        # Flush any pending records
        await self._flush_records()

    async def _initialize_storage(self) -> None:
        """Initialize forensic storage."""
        storage_path = Path(self.config.forensics.storage_path)
        storage_path.mkdir(parents=True, exist_ok=True)

    async def _flush_records(self) -> None:
        """Flush pending records to storage."""
        # In production, write to WORM storage
        pass

    async def log_action(self, mission: Any, action_result: Any) -> ForensicRecord:
        """
        Log action result to forensic record.

        Args:
            mission: Mission context
            action_result: Action execution result

        Returns:
            Created forensic record
        """
        mission_id = mission.mission_id

        # Get previous hash for chain
        previous_hash = self._last_hash.get(mission_id, "genesis")

        # Create record
        record_data = {
            "action_id": str(action_result.action_id),
            "action_type": action_result.action_type,
            "target": action_result.target,
            "status": action_result.status,
            "duration_ms": action_result.duration_ms,
            "impact_score": action_result.impact_score,
            "alerts_generated": action_result.alerts_generated,
            "output": action_result.output,
            "error": action_result.error,
        }

        record_hash = self._compute_record_hash(record_data, previous_hash)

        record = ForensicRecord(
            record_id=uuid4(),
            mission_id=mission_id,
            timestamp=datetime.utcnow(),
            event_type="action_result",
            data=record_data,
            hash=record_hash,
            previous_hash=previous_hash,
            classification_level=mission.classification_level,
        )

        # Store record
        if mission_id not in self._records:
            self._records[mission_id] = []
        self._records[mission_id].append(record)

        # Update last hash
        self._last_hash[mission_id] = record_hash

        # Add external timestamp if enabled
        if self.config.forensics.external_timestamp_enabled:
            await self._add_external_timestamp(record)

        return record

    async def log_event(
        self,
        mission: Any,
        event_type: str,
        data: Dict[str, Any],
    ) -> ForensicRecord:
        """
        Log arbitrary event to forensic record.

        Args:
            mission: Mission context
            event_type: Type of event
            data: Event data

        Returns:
            Created forensic record
        """
        mission_id = mission.mission_id
        previous_hash = self._last_hash.get(mission_id, "genesis")

        record_hash = self._compute_record_hash(data, previous_hash)

        record = ForensicRecord(
            record_id=uuid4(),
            mission_id=mission_id,
            timestamp=datetime.utcnow(),
            event_type=event_type,
            data=data,
            hash=record_hash,
            previous_hash=previous_hash,
            classification_level=mission.classification_level,
        )

        if mission_id not in self._records:
            self._records[mission_id] = []
        self._records[mission_id].append(record)

        self._last_hash[mission_id] = record_hash

        return record

    async def validate_scenario_hash(self, mission: Any) -> bool:
        """
        Validate scenario hash matches expected value.

        Args:
            mission: Mission to validate

        Returns:
            True if hash matches

        Raises:
            ForensicIntegrityError: If hash mismatch
        """
        scenario = mission.scenario
        computed_hash = self._compute_scenario_hash(scenario)

        if mission.scenario_hash and mission.scenario_hash != computed_hash:
            raise ForensicIntegrityError(
                "Scenario hash mismatch",
                expected_hash=mission.scenario_hash,
                actual_hash=computed_hash,
                artifact="scenario",
            )

        mission.scenario_hash = computed_hash
        return True

    async def get_completeness(self, mission: Any) -> float:
        """
        Calculate forensic completeness score.

        Args:
            mission: Mission to calculate completeness for

        Returns:
            Completeness score (0-1)
        """
        mission_id = mission.mission_id
        records = self._records.get(mission_id, [])

        if not records:
            return 0.0

        # Factors for completeness
        factors = {
            "action_coverage": 0.0,
            "chain_integrity": 0.0,
            "timestamp_coverage": 0.0,
            "data_completeness": 0.0,
        }

        # Action coverage - do we have records for all actions?
        if mission.actions_completed > 0:
            action_records = [r for r in records if r.event_type == "action_result"]
            factors["action_coverage"] = min(
                len(action_records) / mission.actions_completed, 1.0
            )

        # Chain integrity - verify hash chain
        factors["chain_integrity"] = await self._verify_chain_integrity(mission_id)

        # Timestamp coverage
        timestamped = sum(1 for r in records if r.timestamp)
        factors["timestamp_coverage"] = timestamped / len(records) if records else 0

        # Data completeness - check for required fields
        complete_records = sum(
            1 for r in records
            if r.data and all(k in r.data for k in ["action_type", "status"])
        )
        factors["data_completeness"] = complete_records / len(records) if records else 0

        # Weighted average
        weights = {
            "action_coverage": 0.3,
            "chain_integrity": 0.3,
            "timestamp_coverage": 0.2,
            "data_completeness": 0.2,
        }

        completeness = sum(
            factors[k] * weights[k] for k in factors
        )

        return completeness

    async def finalize_mission(self, mission: Any) -> str:
        """
        Finalize forensic record for completed mission.

        Args:
            mission: Completed mission

        Returns:
            Final Merkle root hash
        """
        mission_id = mission.mission_id
        records = self._records.get(mission_id, [])

        if not records:
            return ""

        # Build Merkle tree
        merkle_root = self._build_merkle_tree(records)
        self._merkle_roots[mission_id] = merkle_root

        # Update mission lineage hash
        mission.lineage_hash = merkle_root

        # Log finalization event
        await self.log_event(
            mission,
            "mission_finalized",
            {
                "merkle_root": merkle_root,
                "record_count": len(records),
                "completeness": await self.get_completeness(mission),
            },
        )

        logger.info(f"Mission {mission_id} forensics finalized. Merkle root: {merkle_root}")

        return merkle_root

    async def replay_mission(self, mission: Any) -> ReplayResult:
        """
        Replay mission from forensic records.

        Args:
            mission: Mission to replay

        Returns:
            Replay result
        """
        mission_id = mission.mission_id
        records = self._records.get(mission_id, [])

        if not records:
            return ReplayResult(
                mission_id=mission_id,
                success=False,
                completeness=0.0,
                divergences=[{"error": "No forensic records found"}],
                timestamp=datetime.utcnow(),
            )

        divergences = []
        replayed_count = 0

        # Verify chain integrity first
        chain_valid = await self._verify_chain_integrity(mission_id)
        if chain_valid < 1.0:
            divergences.append({
                "type": "chain_integrity",
                "message": f"Chain integrity: {chain_valid:.0%}",
            })

        # Replay each action record
        for record in records:
            if record.event_type == "action_result":
                # Verify record hash
                computed_hash = self._compute_record_hash(
                    record.data, record.previous_hash
                )
                if computed_hash != record.hash:
                    divergences.append({
                        "type": "hash_mismatch",
                        "record_id": str(record.record_id),
                        "expected": record.hash,
                        "computed": computed_hash,
                    })
                else:
                    replayed_count += 1

        # Calculate completeness
        action_records = [r for r in records if r.event_type == "action_result"]
        completeness = replayed_count / len(action_records) if action_records else 0.0

        success = completeness >= self.config.forensics.replay_success_threshold

        return ReplayResult(
            mission_id=mission_id,
            success=success,
            completeness=completeness,
            divergences=divergences,
            timestamp=datetime.utcnow(),
        )

    async def _verify_chain_integrity(self, mission_id: UUID) -> float:
        """Verify hash chain integrity."""
        records = self._records.get(mission_id, [])

        if not records:
            return 1.0

        valid_links = 0
        total_links = len(records)

        previous_hash = "genesis"
        for record in records:
            if record.previous_hash != previous_hash:
                logger.warning(f"Chain break at record {record.record_id}")
            else:
                valid_links += 1

            # Verify record hash
            computed = self._compute_record_hash(record.data, record.previous_hash)
            if computed == record.hash:
                previous_hash = record.hash
            else:
                logger.warning(f"Hash mismatch at record {record.record_id}")

        return valid_links / total_links if total_links > 0 else 1.0

    def _compute_record_hash(
        self, data: Dict[str, Any], previous_hash: str
    ) -> str:
        """Compute hash for forensic record."""
        content = json.dumps(data, sort_keys=True) + previous_hash
        return hashlib.sha256(content.encode()).hexdigest()

    def _compute_scenario_hash(self, scenario: Dict[str, Any]) -> str:
        """Compute hash for scenario."""
        content = json.dumps(scenario, sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def _build_merkle_tree(self, records: List[ForensicRecord]) -> str:
        """Build Merkle tree from records and return root hash."""
        if not records:
            return ""

        # Create leaf hashes
        leaves = [r.hash for r in records]

        # Pad to power of 2
        while len(leaves) & (len(leaves) - 1) != 0:
            leaves.append(leaves[-1])

        # Build tree
        while len(leaves) > 1:
            new_level = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_level.append(new_hash)
            leaves = new_level

        return leaves[0] if leaves else ""

    async def _add_external_timestamp(self, record: ForensicRecord) -> None:
        """Add external timestamp to record."""
        # In production, this would call an external timestamp authority
        # like time.nist.gov or a blockchain timestamp service
        pass

    def get_records(self, mission_id: UUID) -> List[ForensicRecord]:
        """Get all forensic records for a mission."""
        return self._records.get(mission_id, []).copy()

    def get_merkle_root(self, mission_id: UUID) -> Optional[str]:
        """Get Merkle root for a mission."""
        return self._merkle_roots.get(mission_id)
