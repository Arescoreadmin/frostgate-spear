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
