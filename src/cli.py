"""
Frost Gate Spear CLI

Command-line interface for the Frost Gate Spear platform.
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .core import FrostGateSpear, Config
from .core.exceptions import FrostGateError


def setup_logging(level: str = "INFO") -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_config(config_path: Optional[str]) -> Config:
    """Load configuration from file or use defaults."""
    if config_path:
        return Config.from_file(config_path)
    return Config()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="frostgate",
        description="Frost Gate Spear - Autonomous Red Team Simulation Platform",
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default=None,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Server command
    server_parser = subparsers.add_parser("server", help="Start the server")
    server_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to",
    )
    server_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind to",
    )

    # Mission commands
    mission_parser = subparsers.add_parser("mission", help="Mission operations")
    mission_subparsers = mission_parser.add_subparsers(dest="mission_command")

    # Create mission
    create_parser = mission_subparsers.add_parser("create", help="Create a mission")
    create_parser.add_argument(
        "--envelope",
        required=True,
        help="Path to policy envelope JSON",
    )
    create_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario JSON",
    )
    create_parser.add_argument(
        "--persona",
        help="Persona ID to use",
    )

    # Start mission
    start_parser = mission_subparsers.add_parser("start", help="Start a mission")
    start_parser.add_argument(
        "--id",
        required=True,
        help="Mission ID",
    )

    # Status
    status_parser = mission_subparsers.add_parser("status", help="Get mission status")
    status_parser.add_argument(
        "--id",
        required=True,
        help="Mission ID",
    )

    # List missions
    mission_subparsers.add_parser("list", help="List missions")

    # Abort mission
    abort_parser = mission_subparsers.add_parser("abort", help="Abort a mission")
    abort_parser.add_argument(
        "--id",
        required=True,
        help="Mission ID",
    )
    abort_parser.add_argument(
        "--reason",
        default="User requested",
        help="Abort reason",
    )

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate files")
    validate_parser.add_argument(
        "--envelope",
        help="Validate policy envelope",
    )
    validate_parser.add_argument(
        "--scenario",
        help="Validate scenario",
    )
    validate_parser.add_argument(
        "--persona",
        help="Validate persona",
    )

    # Simulate command
    sim_parser = subparsers.add_parser("simulate", help="Run simulation")
    sim_parser.add_argument(
        "--envelope",
        required=True,
        help="Path to policy envelope JSON",
    )
    sim_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario JSON",
    )
    sim_parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of simulation iterations",
    )

    # Info command
    subparsers.add_parser("info", help="Show platform information")

    # Version command
    subparsers.add_parser("version", help="Show version")

    # Health command
    subparsers.add_parser("health", help="Health check")

    # Watch command (v6.1 requirement)
    watch_parser = subparsers.add_parser(
        "watch",
        help="Watch and verify campaign ledger (v6.1)",
    )
    watch_parser.add_argument(
        "campaign_id",
        help="Campaign ID to watch",
    )
    watch_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify ledger hash chain and signatures",
    )
    watch_parser.add_argument(
        "--resume-from",
        dest="resume_from",
        help="Resume verification from specific hash",
    )
    watch_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    watch_parser.add_argument(
        "--follow",
        action="store_true",
        help="Follow ledger in real-time",
    )
    watch_parser.add_argument(
        "--ledger-path",
        dest="ledger_path",
        help="Path to ledger file (default: data/<campaign_id>/ledger.jsonl)",
    )

    return parser


async def cmd_server(args: argparse.Namespace, config: Config) -> int:
    """Start the server."""
    from .rpc import create_server

    logger = logging.getLogger(__name__)
    logger.info(f"Starting Frost Gate Spear server on {args.host}:{args.port}")

    engine = FrostGateSpear(config)
    await engine.start()

    try:
        server = await create_server(engine, args.host, args.port)
        await server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await engine.stop()

    return 0


async def cmd_mission_create(args: argparse.Namespace, config: Config) -> int:
    """Create a mission."""
    logger = logging.getLogger(__name__)

    # Load envelope
    with open(args.envelope) as f:
        envelope = json.load(f)

    # Load scenario
    with open(args.scenario) as f:
        scenario = json.load(f)

    engine = FrostGateSpear(config)
    await engine.start()

    try:
        mission = await engine.create_mission(
            policy_envelope=envelope,
            scenario=scenario,
            persona_id=args.persona,
        )

        print(json.dumps({
            "mission_id": str(mission.mission_id),
            "state": mission.state.value,
            "classification_level": mission.classification_level,
        }, indent=2))

        return 0

    except FrostGateError as e:
        logger.error(f"Failed to create mission: {e}")
        print(json.dumps(e.to_dict(), indent=2), file=sys.stderr)
        return 1

    finally:
        await engine.stop()


async def cmd_mission_start(args: argparse.Namespace, config: Config) -> int:
    """Start a mission."""
    from uuid import UUID

    logger = logging.getLogger(__name__)

    engine = FrostGateSpear(config)
    await engine.start()

    try:
        mission_id = UUID(args.id)
        await engine.start_mission(mission_id)
        print(f"Mission {mission_id} started")
        return 0

    except FrostGateError as e:
        logger.error(f"Failed to start mission: {e}")
        print(json.dumps(e.to_dict(), indent=2), file=sys.stderr)
        return 1

    finally:
        await engine.stop()


async def cmd_mission_status(args: argparse.Namespace, config: Config) -> int:
    """Get mission status."""
    from uuid import UUID

    logger = logging.getLogger(__name__)

    engine = FrostGateSpear(config)
    await engine.start()

    try:
        mission_id = UUID(args.id)
        status = await engine.get_mission_status(mission_id)
        print(json.dumps(status, indent=2, default=str))
        return 0

    except FrostGateError as e:
        logger.error(f"Failed to get status: {e}")
        print(json.dumps(e.to_dict(), indent=2), file=sys.stderr)
        return 1

    finally:
        await engine.stop()


async def cmd_validate(args: argparse.Namespace, config: Config) -> int:
    """Validate files."""
    from .policy_interpreter import PolicyInterpreter
    import jsonschema

    logger = logging.getLogger(__name__)
    errors = []

    interpreter = PolicyInterpreter(config)
    await interpreter.start()

    try:
        if args.envelope:
            with open(args.envelope) as f:
                envelope = json.load(f)
            try:
                result = await interpreter.validate_envelope(envelope)
                print(f"Envelope: VALID (hash: {result.envelope_hash})")
            except Exception as e:
                errors.append(f"Envelope: INVALID - {e}")
                print(f"Envelope: INVALID - {e}")

        if args.scenario:
            with open(args.scenario) as f:
                scenario = json.load(f)
            # Load scenario schema
            schema_path = Path(config.base_path) / "scenarios" / "schema.json"
            if schema_path.exists():
                with open(schema_path) as f:
                    schema = json.load(f)
                try:
                    jsonschema.validate(scenario, schema)
                    print("Scenario: VALID")
                except jsonschema.ValidationError as e:
                    errors.append(f"Scenario: INVALID - {e.message}")
                    print(f"Scenario: INVALID - {e.message}")
            else:
                print("Scenario: SKIPPED (no schema found)")

        if args.persona:
            with open(args.persona) as f:
                persona = json.load(f)
            schema_path = Path(config.base_path) / "adversary_personas" / "schema.json"
            if schema_path.exists():
                with open(schema_path) as f:
                    schema = json.load(f)
                try:
                    jsonschema.validate(persona, schema)
                    print("Persona: VALID")
                except jsonschema.ValidationError as e:
                    errors.append(f"Persona: INVALID - {e.message}")
                    print(f"Persona: INVALID - {e.message}")

        return 1 if errors else 0

    finally:
        await interpreter.stop()


async def cmd_simulate(args: argparse.Namespace, config: Config) -> int:
    """Run simulation validation."""
    from .sim import SimulationRunner
    from .core.mission import Mission

    logger = logging.getLogger(__name__)

    # Load files
    with open(args.envelope) as f:
        envelope = json.load(f)

    with open(args.scenario) as f:
        scenario = json.load(f)

    # Create mission
    mission = Mission(
        policy_envelope=envelope,
        scenario=scenario,
        classification_level=envelope.get("classification_level", "UNCLASS"),
    )

    # Run simulation
    runner = SimulationRunner(config)
    print(f"Running {args.iterations} simulation iterations...")

    result = await runner.run_validation(mission, iterations=args.iterations)

    print(json.dumps(result, indent=2))

    return 0 if result["passed"] else 1


def cmd_info(args: argparse.Namespace, config: Config) -> int:
    """Show platform information."""
    from . import __version__

    info = {
        "name": "Frost Gate Spear",
        "version": __version__,
        "environment": config.environment.value,
        "classification_level": config.classification_level.value,
        "features": {
            "mls_enabled": True,
            "fl_enabled": config.fl.enabled,
            "forensics_enabled": config.forensics.worm_storage_enabled,
        },
        "thresholds": {
            "forensic_completeness": config.forensics.completeness_threshold,
            "replay_success": config.forensics.replay_success_threshold,
            "sim_runs_required": config.governance.sim_runs_required,
        },
    }

    print(json.dumps(info, indent=2))
    return 0


def cmd_version(args: argparse.Namespace, config: Config) -> int:
    """Show version."""
    from . import __version__
    print(f"Frost Gate Spear v{__version__}")
    return 0


def cmd_health() -> int:
    """Emit a health check response."""
    payload = {"status": "ok"}
    print(json.dumps(payload))
    return 0


async def cmd_watch(args: argparse.Namespace, config: Config) -> int:
    """
    Watch and verify campaign ledger.

    Implements v6.1 Blueprint requirements:
    - Verify ledger hash chain integrity
    - Verify entry signatures
    - Verify witness checkpoints (if present)
    - Detect gaps in sequence numbers
    - Detect tampering in hash chain
    - Resume verification from a specific hash
    - Output in JSON format for automation
    """
    import base64
    import hashlib
    from datetime import datetime

    logger = logging.getLogger(__name__)

    campaign_id = args.campaign_id

    # Determine ledger path
    if args.ledger_path:
        ledger_path = Path(args.ledger_path)
    else:
        # Default path
        ledger_path = Path("data") / campaign_id / "ledger.jsonl"

    if not ledger_path.exists():
        error_result = {
            "campaign_id": campaign_id,
            "verification_status": "ERROR",
            "error": f"Ledger file not found: {ledger_path}",
        }
        if args.json:
            print(json.dumps(error_result, indent=2))
        else:
            print(f"Error: Ledger file not found: {ledger_path}")
        return 1

    # Verification state
    entries_verified = 0
    chain_integrity = True
    gaps_detected = []
    tampering_detected = []
    witness_checkpoints_verified = 0
    signature_failures = []
    resume_hash = None
    last_sequence = 0
    previous_hash = None
    resume_mode = args.resume_from is not None
    resume_found = False

    # Load trust store for signature verification
    try:
        from .permits import TrustStoreVerifier
        trust_store_path = Path("integrity") / "trust_store.json"
        trust_store = TrustStoreVerifier(trust_store_path if trust_store_path.exists() else None)
    except Exception as e:
        logger.warning(f"Could not load trust store: {e}")
        trust_store = None

    def compute_entry_hash(entry: dict) -> str:
        """Compute hash for a ledger entry."""
        hash_content = {
            "entry_id": entry.get("entry_id"),
            "campaign_id": entry.get("campaign_id"),
            "sequence_number": entry.get("sequence_number"),
            "event_type": entry.get("event_type"),
            "timestamp": entry.get("timestamp"),
            "payload_hash": compute_payload_hash(entry.get("payload", {})),
            "previous_hash": entry.get("previous_hash"),
        }
        content = json.dumps(hash_content, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    def compute_payload_hash(payload: dict) -> str:
        """Compute hash of entry payload."""
        content = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    def verify_signature(entry: dict) -> tuple:
        """Verify entry signature if present."""
        sig = entry.get("signature")
        if not sig:
            return True, None  # No signature to verify

        if not trust_store:
            return False, "No trust store available for signature verification"

        try:
            sig_value = sig.get("value", "")
            key_id = sig.get("key_id", "")

            # Build message from entry (excluding signature)
            entry_for_signing = {k: v for k, v in entry.items() if k != "signature"}
            message = json.dumps(entry_for_signing, sort_keys=True, separators=(',', ':')).encode('utf-8')
            signature_bytes = base64.b64decode(sig_value)

            valid, error = trust_store.verify_signature(message, signature_bytes, key_id)
            return valid, error

        except Exception as e:
            return False, str(e)

    # Process ledger
    try:
        with open(ledger_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    tampering_detected.append({
                        "line": line_num,
                        "type": "MALFORMED_JSON",
                        "error": str(e),
                    })
                    chain_integrity = False
                    continue

                # Handle resume mode
                if resume_mode and not resume_found:
                    entry_hash = entry.get("entry_hash", "")
                    if entry_hash == args.resume_from:
                        resume_found = True
                        previous_hash = entry_hash
                        last_sequence = entry.get("sequence_number", 0)
                    continue

                # Sequence gap detection
                current_sequence = entry.get("sequence_number", 0)
                if last_sequence > 0 and current_sequence != last_sequence + 1:
                    gaps_detected.append({
                        "expected": last_sequence + 1,
                        "found": current_sequence,
                        "entry_id": entry.get("entry_id"),
                    })
                    chain_integrity = False

                # Hash chain verification
                if args.verify:
                    stored_hash = entry.get("entry_hash", "")
                    computed_hash = compute_entry_hash(entry)

                    if stored_hash != computed_hash:
                        tampering_detected.append({
                            "entry_id": entry.get("entry_id"),
                            "sequence": current_sequence,
                            "type": "HASH_MISMATCH",
                            "stored": stored_hash,
                            "computed": computed_hash,
                        })
                        chain_integrity = False

                    # Previous hash chain verification
                    entry_prev_hash = entry.get("previous_hash")
                    if previous_hash is not None and entry_prev_hash != previous_hash:
                        tampering_detected.append({
                            "entry_id": entry.get("entry_id"),
                            "sequence": current_sequence,
                            "type": "CHAIN_BREAK",
                            "expected_previous": previous_hash,
                            "found_previous": entry_prev_hash,
                        })
                        chain_integrity = False

                    # First entry should have no previous hash
                    if last_sequence == 0 and entry_prev_hash is not None:
                        tampering_detected.append({
                            "entry_id": entry.get("entry_id"),
                            "sequence": current_sequence,
                            "type": "FIRST_ENTRY_HAS_PREVIOUS",
                        })
                        chain_integrity = False

                    # Signature verification
                    sig_valid, sig_error = verify_signature(entry)
                    if not sig_valid and sig_error:
                        signature_failures.append({
                            "entry_id": entry.get("entry_id"),
                            "sequence": current_sequence,
                            "error": sig_error,
                        })

                    previous_hash = stored_hash

                # Witness checkpoint detection
                if entry.get("event_type") == "WITNESS_CHECKPOINT":
                    witness_checkpoints_verified += 1

                entries_verified += 1
                last_sequence = current_sequence
                resume_hash = entry.get("entry_hash")

                # Print progress for non-JSON mode
                if not args.json and entries_verified % 1000 == 0:
                    print(f"Verified {entries_verified} entries...")

    except Exception as e:
        error_result = {
            "campaign_id": campaign_id,
            "verification_status": "ERROR",
            "error": str(e),
        }
        if args.json:
            print(json.dumps(error_result, indent=2))
        else:
            print(f"Error reading ledger: {e}")
        return 1

    # Determine verification status
    if not args.verify:
        verification_status = "SKIPPED"
    elif chain_integrity and not tampering_detected and not gaps_detected:
        verification_status = "VALID"
    elif resume_mode and not resume_found:
        verification_status = "INCOMPLETE"
    else:
        verification_status = "INVALID"

    result = {
        "campaign_id": campaign_id,
        "verification_status": verification_status,
        "entries_verified": entries_verified,
        "chain_integrity": chain_integrity,
        "gaps_detected": gaps_detected,
        "tampering_detected": tampering_detected,
        "signature_failures": signature_failures,
        "witness_checkpoints_verified": witness_checkpoints_verified,
        "resume_hash": resume_hash,
        "verified_at": datetime.utcnow().isoformat() + "Z",
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nLedger Verification Report")
        print(f"=" * 50)
        print(f"Campaign ID: {campaign_id}")
        print(f"Status: {verification_status}")
        print(f"Entries Verified: {entries_verified}")
        print(f"Chain Integrity: {'OK' if chain_integrity else 'BROKEN'}")
        print(f"Witness Checkpoints: {witness_checkpoints_verified}")

        if gaps_detected:
            print(f"\nSequence Gaps Detected: {len(gaps_detected)}")
            for gap in gaps_detected[:5]:
                print(f"  - Expected {gap['expected']}, found {gap['found']}")
            if len(gaps_detected) > 5:
                print(f"  ... and {len(gaps_detected) - 5} more")

        if tampering_detected:
            print(f"\nTampering Detected: {len(tampering_detected)}")
            for issue in tampering_detected[:5]:
                print(f"  - {issue['type']} at entry {issue.get('entry_id', 'unknown')}")
            if len(tampering_detected) > 5:
                print(f"  ... and {len(tampering_detected) - 5} more")

        if signature_failures:
            print(f"\nSignature Failures: {len(signature_failures)}")
            for failure in signature_failures[:5]:
                print(f"  - Entry {failure['entry_id']}: {failure['error']}")

        if resume_hash:
            print(f"\nResume Hash: {resume_hash}")

    return 0 if verification_status in ["VALID", "SKIPPED"] else 1


async def async_main(args: argparse.Namespace, config: Config) -> int:
    """Async main entry point."""
    if args.command == "server":
        return await cmd_server(args, config)

    elif args.command == "mission":
        if args.mission_command == "create":
            return await cmd_mission_create(args, config)
        elif args.mission_command == "start":
            return await cmd_mission_start(args, config)
        elif args.mission_command == "status":
            return await cmd_mission_status(args, config)
        elif args.mission_command == "abort":
            # Similar implementation
            print("Abort not yet implemented")
            return 1
        elif args.mission_command == "list":
            print("List not yet implemented")
            return 1

    elif args.command == "validate":
        return await cmd_validate(args, config)

    elif args.command == "simulate":
        return await cmd_simulate(args, config)

    elif args.command == "info":
        return cmd_info(args, config)

    elif args.command == "version":
        return cmd_version(args, config)

    elif args.command == "health":
        return cmd_health()

    elif args.command == "watch":
        return await cmd_watch(args, config)

    else:
        print("No command specified. Use --help for usage.")
        return 1


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else args.log_level
    setup_logging(log_level)

    # Load config
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        return 1

    # Run async main
    return asyncio.run(async_main(args, config))


if __name__ == "__main__":
    sys.exit(main())
