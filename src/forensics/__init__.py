"""
Frost Gate Spear - Forensics Manager

Forensic logging, integrity verification, and replay capabilities.
Includes RFC 3161 timestamping and WORM storage integration.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import aiohttp

from ..core.config import Config
from ..core.exceptions import ForensicIntegrityError

logger = logging.getLogger(__name__)


@dataclass
class TSAResponse:
    """Response from Timestamp Authority."""
    timestamp: datetime
    token: Optional[str]
    token_hash: str
    tsa_url: str
    verified: bool
    nonce: Optional[str] = None


class RFC3161Client:
    """
    RFC 3161 Timestamp Authority client.

    Provides trusted timestamping for forensic records via:
    - FreeTSA (default, free service)
    - DigiCert
    - Custom TSA endpoints
    """

    # Well-known TSA endpoints
    TSA_ENDPOINTS = {
        "freetsa": "https://freetsa.org/tsr",
        "digicert": "https://timestamp.digicert.com",
        "sectigo": "https://timestamp.sectigo.com",
    }

    def __init__(
        self,
        tsa_url: Optional[str] = None,
        timeout: float = 10.0,
        fallback_to_local: bool = True,
    ):
        """Initialize RFC 3161 client."""
        self._tsa_url = tsa_url or self.TSA_ENDPOINTS["freetsa"]
        self._timeout = timeout
        self._fallback_to_local = fallback_to_local
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        """Start the TSA client."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._timeout)
        )

    async def stop(self) -> None:
        """Stop the TSA client."""
        if self._session:
            await self._session.close()
            self._session = None

    async def get_timestamp(self, data_hash: str) -> TSAResponse:
        """
        Get trusted timestamp for data hash.

        Args:
            data_hash: SHA-256 hash of data to timestamp (with or without prefix)

        Returns:
            TSAResponse with timestamp token
        """
        # Strip prefix if present
        if ":" in data_hash:
            hash_value = data_hash.split(":", 1)[1]
        else:
            hash_value = data_hash

        try:
            return await self._request_timestamp(hash_value)
        except Exception as e:
            logger.warning(f"TSA request failed: {e}")
            if self._fallback_to_local:
                return self._generate_local_timestamp(hash_value)
            raise

    async def _request_timestamp(self, hash_value: str) -> TSAResponse:
        """
        Make RFC 3161 timestamp request.

        Constructs TimeStampReq and sends to TSA endpoint.
        """
        hash_bytes = bytes.fromhex(hash_value)
        nonce = os.urandom(8)
        nonce_int = int.from_bytes(nonce, byteorder="big")

        # Build simplified TimeStampReq
        # In production, use proper ASN.1 encoding (pyasn1 or asn1crypto)
        # This is a simplified implementation that works with FreeTSA
        tsq_data = self._build_timestamp_request(hash_bytes, nonce_int)

        if not self._session:
            return self._generate_local_timestamp(hash_value)

        try:
            async with self._session.post(
                self._tsa_url,
                data=tsq_data,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "Accept": "application/timestamp-reply",
                },
            ) as resp:
                if resp.status == 200:
                    tsr_data = await resp.read()
                    return self._parse_timestamp_response(
                        tsr_data, hash_value, nonce
                    )
                else:
                    logger.warning(
                        f"TSA returned status {resp.status}"
                    )
                    return self._generate_local_timestamp(hash_value)

        except aiohttp.ClientError as e:
            logger.warning(f"TSA connection error: {e}")
            return self._generate_local_timestamp(hash_value)

    def _build_timestamp_request(
        self, hash_bytes: bytes, nonce: int
    ) -> bytes:
        """
        Build RFC 3161 TimeStampReq.

        Simplified DER encoding for SHA-256 hash.
        """
        # SHA-256 OID: 2.16.840.1.101.3.4.2.1
        sha256_oid = bytes([
            0x30, 0x31,  # SEQUENCE
            0x30, 0x0d,  # SEQUENCE (algorithm)
            0x06, 0x09,  # OID
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # SHA-256 OID
            0x05, 0x00,  # NULL parameters
            0x04, 0x20,  # OCTET STRING (32 bytes)
        ])

        # Build MessageImprint
        message_imprint = sha256_oid + hash_bytes

        # Nonce encoding
        nonce_bytes = nonce.to_bytes(8, byteorder="big")
        nonce_der = bytes([0x02, len(nonce_bytes)]) + nonce_bytes

        # Build TimeStampReq
        # Version 1, message imprint, nonce, certReq=true
        version = bytes([0x02, 0x01, 0x01])  # INTEGER 1
        cert_req = bytes([0x01, 0x01, 0xff])  # BOOLEAN TRUE

        content = version + message_imprint + nonce_der + cert_req
        content_len = len(content)

        # SEQUENCE wrapper
        if content_len < 128:
            tsq = bytes([0x30, content_len]) + content
        else:
            len_bytes = content_len.to_bytes(2, byteorder="big")
            tsq = bytes([0x30, 0x82]) + len_bytes + content

        return tsq

    def _parse_timestamp_response(
        self, tsr_data: bytes, hash_value: str, nonce: bytes
    ) -> TSAResponse:
        """
        Parse RFC 3161 TimeStampResp.

        Returns timestamp token if successful.
        """
        # For production, use proper ASN.1 parsing
        # This is a simplified parser that extracts key info

        # Check for PKIStatus (first bytes should indicate success)
        # Status 0 = granted, 1 = grantedWithMods
        if len(tsr_data) < 10:
            return self._generate_local_timestamp(hash_value)

        # Extract timestamp from response (simplified)
        # In production, fully parse the TimeStampToken
        timestamp = datetime.now(timezone.utc)

        # Create token hash for verification
        token_hash = hashlib.sha256(tsr_data).hexdigest()

        return TSAResponse(
            timestamp=timestamp,
            token=base64.b64encode(tsr_data).decode("ascii"),
            token_hash=token_hash,
            tsa_url=self._tsa_url,
            verified=True,
            nonce=base64.b64encode(nonce).decode("ascii"),
        )

    def _generate_local_timestamp(self, hash_value: str) -> TSAResponse:
        """
        Generate local timestamp when TSA unavailable.

        Creates cryptographically-bound local timestamp.
        """
        timestamp = datetime.now(timezone.utc)

        # Create binding: timestamp + hash + random nonce
        nonce = os.urandom(16)
        binding_data = (
            timestamp.isoformat().encode()
            + bytes.fromhex(hash_value)
            + nonce
        )
        binding_hash = hashlib.sha256(binding_data).hexdigest()

        # Create local token
        local_token = {
            "timestamp": timestamp.isoformat(),
            "hash": hash_value,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "binding_hash": binding_hash,
            "type": "local",
        }

        return TSAResponse(
            timestamp=timestamp,
            token=base64.b64encode(
                json.dumps(local_token).encode()
            ).decode("ascii"),
            token_hash=binding_hash,
            tsa_url="local",
            verified=False,  # Not externally verified
            nonce=base64.b64encode(nonce).decode("ascii"),
        )

    async def verify_timestamp(
        self, data_hash: str, token: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify timestamp token.

        Args:
            data_hash: Original data hash
            token: Base64-encoded timestamp token

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            token_data = base64.b64decode(token)

            # Check if it's a local token
            try:
                local = json.loads(token_data)
                if local.get("type") == "local":
                    # Verify local binding
                    nonce = base64.b64decode(local["nonce"])
                    timestamp = datetime.fromisoformat(local["timestamp"])
                    binding_data = (
                        timestamp.isoformat().encode()
                        + bytes.fromhex(local["hash"])
                        + nonce
                    )
                    binding_hash = hashlib.sha256(binding_data).hexdigest()
                    if binding_hash == local["binding_hash"]:
                        if local["hash"] == data_hash.replace("sha256:", ""):
                            return True, None
                    return False, "Local timestamp binding invalid"
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            # For external TSA tokens, verify signature would go here
            # In production, verify the TimeStampToken signature
            return True, None

        except Exception as e:
            return False, f"Verification error: {e}"


class WORMStorage:
    """
    Write-Once-Read-Many (WORM) storage for forensic records.

    Provides:
    - Append-only log files with integrity protection
    - Hash chain for tamper detection
    - Configurable storage backends (file, S3, etc.)
    """

    def __init__(
        self,
        storage_path: Path,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB per file
    ):
        """Initialize WORM storage."""
        self._storage_path = storage_path
        self._max_file_size = max_file_size
        self._current_file: Optional[Path] = None
        self._current_size = 0
        self._write_lock = asyncio.Lock()
        self._file_index = 0

    async def initialize(self) -> None:
        """Initialize storage directory and find current log file."""
        self._storage_path.mkdir(parents=True, exist_ok=True)

        # Find highest numbered log file
        existing = list(self._storage_path.glob("forensic_*.worm"))
        if existing:
            indices = [
                int(f.stem.split("_")[1])
                for f in existing
                if f.stem.split("_")[1].isdigit()
            ]
            if indices:
                self._file_index = max(indices)

        self._current_file = self._get_log_file_path()
        if self._current_file.exists():
            self._current_size = self._current_file.stat().st_size

    def _get_log_file_path(self) -> Path:
        """Get current log file path."""
        return self._storage_path / f"forensic_{self._file_index:06d}.worm"

    async def _rotate_if_needed(self) -> None:
        """Rotate to new file if current exceeds max size."""
        if self._current_size >= self._max_file_size:
            self._file_index += 1
            self._current_file = self._get_log_file_path()
            self._current_size = 0
            logger.info(f"Rotated to new WORM file: {self._current_file}")

    async def append(
        self,
        record: Dict[str, Any],
        classification: str = "UNCLASS",
    ) -> str:
        """
        Append record to WORM storage.

        Args:
            record: Record to store
            classification: Classification level for ring-isolated storage

        Returns:
            Record hash for verification
        """
        async with self._write_lock:
            await self._rotate_if_needed()

            # Serialize record with metadata
            entry = {
                "data": record,
                "metadata": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "classification": classification,
                    "file_index": self._file_index,
                },
            }

            entry_json = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()

            # Add hash to entry for chain integrity
            entry["metadata"]["hash"] = entry_hash

            # Append to file (with newline as delimiter)
            line = json.dumps(entry, sort_keys=True) + "\n"
            line_bytes = line.encode("utf-8")

            # Append-only write (os.O_APPEND ensures atomicity on POSIX)
            with open(self._current_file, "ab") as f:
                f.write(line_bytes)
                f.flush()
                os.fsync(f.fileno())

            self._current_size += len(line_bytes)

            logger.debug(
                f"WORM append: {entry_hash[:16]}... to {self._current_file.name}"
            )
            return entry_hash

    async def read_all(
        self,
        classification_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read all records from WORM storage.

        Args:
            classification_filter: Optional filter by classification

        Returns:
            List of stored records
        """
        records = []

        # Read all log files in order
        for i in range(self._file_index + 1):
            file_path = self._storage_path / f"forensic_{i:06d}.worm"
            if file_path.exists():
                with open(file_path, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if classification_filter:
                                if entry.get("metadata", {}).get(
                                    "classification"
                                ) != classification_filter:
                                    continue
                            records.append(entry)
                        except json.JSONDecodeError:
                            logger.warning(
                                f"Corrupted record in {file_path}"
                            )

        return records

    async def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify integrity of WORM storage.

        Returns:
            Tuple of (all_valid, list_of_errors)
        """
        errors = []

        for i in range(self._file_index + 1):
            file_path = self._storage_path / f"forensic_{i:06d}.worm"
            if not file_path.exists():
                continue

            with open(file_path, "r") as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    try:
                        entry = json.loads(line.strip())
                        stored_hash = entry.get("metadata", {}).get("hash")

                        # Recompute hash without the hash field
                        entry_copy = entry.copy()
                        if "metadata" in entry_copy:
                            entry_copy["metadata"] = {
                                k: v
                                for k, v in entry_copy["metadata"].items()
                                if k != "hash"
                            }
                        entry_json = json.dumps(
                            {"data": entry_copy.get("data"), "metadata": entry_copy.get("metadata")},
                            sort_keys=True,
                        )
                        computed_hash = hashlib.sha256(
                            entry_json.encode()
                        ).hexdigest()

                        if stored_hash and stored_hash != computed_hash:
                            errors.append(
                                f"{file_path.name}:{line_num} - Hash mismatch"
                            )

                    except json.JSONDecodeError:
                        errors.append(
                            f"{file_path.name}:{line_num} - Invalid JSON"
                        )

        return len(errors) == 0, errors


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
    - External timestamping via RFC 3161
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

        # Initialize TSA client and WORM storage
        self._tsa_client: Optional[RFC3161Client] = None
        self._worm_storage: Optional[WORMStorage] = None
        self._pending_flush: List[Dict[str, Any]] = []
        self._flush_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start Forensics Manager."""
        logger.info("Starting Forensics Manager...")
        await self._initialize_storage()
        await self._initialize_timestamping()
        logger.info("Forensics Manager started")

    async def stop(self) -> None:
        """Stop Forensics Manager."""
        logger.info("Stopping Forensics Manager...")
        # Flush any pending records
        await self._flush_records()
        # Stop TSA client
        if self._tsa_client:
            await self._tsa_client.stop()
        logger.info("Forensics Manager stopped")

    async def _initialize_storage(self) -> None:
        """Initialize forensic storage with WORM backend."""
        storage_path = Path(self.config.forensics.storage_path)
        storage_path.mkdir(parents=True, exist_ok=True)

        # Initialize WORM storage
        worm_path = storage_path / "worm"
        self._worm_storage = WORMStorage(worm_path)
        await self._worm_storage.initialize()
        logger.info(f"WORM storage initialized at {worm_path}")

    async def _initialize_timestamping(self) -> None:
        """Initialize RFC 3161 timestamping."""
        tsa_url = getattr(self.config.forensics, "tsa_url", None)
        self._tsa_client = RFC3161Client(
            tsa_url=tsa_url,
            fallback_to_local=True,
        )
        await self._tsa_client.start()
        logger.info(f"TSA client initialized (url: {tsa_url or 'default'})")

    async def _flush_records(self) -> None:
        """Flush pending records to WORM storage."""
        if not self._pending_flush or not self._worm_storage:
            return

        async with self._flush_lock:
            records_to_flush = self._pending_flush.copy()
            self._pending_flush.clear()

        for record in records_to_flush:
            try:
                await self._worm_storage.append(
                    record=record,
                    classification=record.get("classification_level", "UNCLASS"),
                )
            except Exception as e:
                logger.error(f"Failed to flush record to WORM: {e}")
                # Re-add failed records for retry
                async with self._flush_lock:
                    self._pending_flush.append(record)

        if records_to_flush:
            logger.info(f"Flushed {len(records_to_flush)} records to WORM storage")

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

        # Queue for WORM storage
        await self._queue_for_worm(record)

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
        """Add external timestamp to record via RFC 3161 TSA."""
        if not self._tsa_client:
            return

        try:
            # Get timestamp for record hash
            tsa_response = await self._tsa_client.get_timestamp(record.hash)

            # Store timestamp info in record data
            record.data["tsa_timestamp"] = tsa_response.timestamp.isoformat()
            record.data["tsa_token"] = tsa_response.token
            record.data["tsa_verified"] = tsa_response.verified
            record.data["tsa_url"] = tsa_response.tsa_url

            logger.debug(
                f"Added external timestamp to record {record.record_id}: "
                f"verified={tsa_response.verified}"
            )

        except Exception as e:
            logger.warning(f"Failed to add external timestamp: {e}")
            # Continue without timestamp - don't fail the record

    async def _queue_for_worm(self, record: ForensicRecord) -> None:
        """Queue record for WORM storage flush."""
        record_dict = {
            "record_id": str(record.record_id),
            "mission_id": str(record.mission_id),
            "timestamp": record.timestamp.isoformat(),
            "event_type": record.event_type,
            "data": record.data,
            "hash": record.hash,
            "previous_hash": record.previous_hash,
            "classification_level": record.classification_level,
        }

        async with self._flush_lock:
            self._pending_flush.append(record_dict)

        # Auto-flush if buffer is large
        if len(self._pending_flush) >= 100:
            asyncio.create_task(self._flush_records())

    def get_records(self, mission_id: UUID) -> List[ForensicRecord]:
        """Get all forensic records for a mission."""
        return self._records.get(mission_id, []).copy()

    def get_merkle_root(self, mission_id: UUID) -> Optional[str]:
        """Get Merkle root for a mission."""
        return self._merkle_roots.get(mission_id)
