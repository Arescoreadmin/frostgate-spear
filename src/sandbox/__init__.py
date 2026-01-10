"""
Frost Gate Spear - Tool Sandbox Execution

Docker-isolated execution environment for security tools with
resource constraints, network isolation, and secure cleanup.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from ..core.config import Config
from ..core.exceptions import FrostGateError

logger = logging.getLogger(__name__)


class SandboxError(FrostGateError):
    """Sandbox execution error."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, "SANDBOX_ERROR", **kwargs)


class SandboxState(Enum):
    """Sandbox container state."""
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    TERMINATED = "terminated"


class IsolationLevel(Enum):
    """Container isolation level."""
    MINIMAL = "minimal"      # Basic isolation
    STANDARD = "standard"    # Standard isolation with resource limits
    STRICT = "strict"        # Strict isolation with no network
    MAXIMUM = "maximum"      # Maximum isolation for critical tools


@dataclass
class ResourceLimits:
    """Container resource limits."""
    cpu_cores: float = 1.0
    memory_mb: int = 512
    memory_swap_mb: int = 0
    disk_mb: int = 1024
    pids_limit: int = 100
    ulimit_nofile: int = 1024
    ulimit_nproc: int = 256

    def to_docker_config(self) -> Dict[str, Any]:
        """Convert to Docker SDK config."""
        return {
            "cpu_period": 100000,
            "cpu_quota": int(self.cpu_cores * 100000),
            "mem_limit": f"{self.memory_mb}m",
            "memswap_limit": f"{self.memory_mb + self.memory_swap_mb}m" if self.memory_swap_mb else f"{self.memory_mb}m",
            "pids_limit": self.pids_limit,
            "ulimits": [
                {"Name": "nofile", "Soft": self.ulimit_nofile, "Hard": self.ulimit_nofile},
                {"Name": "nproc", "Soft": self.ulimit_nproc, "Hard": self.ulimit_nproc},
            ],
        }


@dataclass
class NetworkPolicy:
    """Container network policy."""
    enabled: bool = False
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    use_isolated_network: bool = True

    def to_docker_config(self) -> Dict[str, Any]:
        """Convert to Docker network config."""
        if not self.enabled:
            return {"network_mode": "none"}

        if self.use_isolated_network:
            return {"network_mode": "frostgate-sandbox-net"}

        return {"network_mode": "bridge"}


@dataclass
class SecurityPolicy:
    """Container security policy."""
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    drop_all_caps: bool = True
    allowed_caps: List[str] = field(default_factory=list)
    seccomp_profile: Optional[str] = None
    apparmor_profile: Optional[str] = None
    user: str = "nobody:nogroup"

    def to_docker_config(self) -> Dict[str, Any]:
        """Convert to Docker security config."""
        config = {
            "read_only": self.read_only_rootfs,
            "security_opt": [],
            "user": self.user,
        }

        if self.no_new_privileges:
            config["security_opt"].append("no-new-privileges:true")

        if self.seccomp_profile:
            config["security_opt"].append(f"seccomp={self.seccomp_profile}")

        if self.apparmor_profile:
            config["security_opt"].append(f"apparmor={self.apparmor_profile}")

        # Capability handling
        if self.drop_all_caps:
            config["cap_drop"] = ["ALL"]
            if self.allowed_caps:
                config["cap_add"] = self.allowed_caps

        return config


@dataclass
class SandboxConfig:
    """Complete sandbox configuration."""
    isolation_level: IsolationLevel = IsolationLevel.STANDARD
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    network_policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    security_policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    timeout_seconds: int = 300
    working_dir: str = "/workspace"
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def for_isolation_level(cls, level: IsolationLevel) -> "SandboxConfig":
        """Create config for isolation level."""
        configs = {
            IsolationLevel.MINIMAL: cls(
                isolation_level=level,
                resource_limits=ResourceLimits(cpu_cores=2.0, memory_mb=2048),
                network_policy=NetworkPolicy(enabled=True),
                security_policy=SecurityPolicy(read_only_rootfs=False, drop_all_caps=False),
            ),
            IsolationLevel.STANDARD: cls(
                isolation_level=level,
                resource_limits=ResourceLimits(cpu_cores=1.0, memory_mb=1024),
                network_policy=NetworkPolicy(enabled=True, use_isolated_network=True),
                security_policy=SecurityPolicy(),
            ),
            IsolationLevel.STRICT: cls(
                isolation_level=level,
                resource_limits=ResourceLimits(cpu_cores=0.5, memory_mb=512),
                network_policy=NetworkPolicy(enabled=False),
                security_policy=SecurityPolicy(allowed_caps=[]),
            ),
            IsolationLevel.MAXIMUM: cls(
                isolation_level=level,
                resource_limits=ResourceLimits(cpu_cores=0.25, memory_mb=256, pids_limit=50),
                network_policy=NetworkPolicy(enabled=False),
                security_policy=SecurityPolicy(
                    allowed_caps=[],
                    seccomp_profile="default",
                ),
                timeout_seconds=60,
            ),
        }
        return configs.get(level, configs[IsolationLevel.STANDARD])


@dataclass
class ToolExecutionRequest:
    """Request to execute a tool in sandbox."""
    request_id: UUID
    tool_id: str
    tool_image: str
    command: List[str]
    arguments: Dict[str, Any]
    input_files: Dict[str, bytes] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    sandbox_config: Optional[SandboxConfig] = None
    classification_level: str = "UNCLASS"
    mission_id: Optional[UUID] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "request_id": str(self.request_id),
            "tool_id": self.tool_id,
            "tool_image": self.tool_image,
            "command": self.command,
            "arguments": self.arguments,
            "classification_level": self.classification_level,
            "mission_id": str(self.mission_id) if self.mission_id else None,
        }


@dataclass
class ToolExecutionResult:
    """Result of tool execution in sandbox."""
    request_id: UUID
    tool_id: str
    state: SandboxState
    exit_code: int
    stdout: str
    stderr: str
    output_files: Dict[str, bytes] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    container_id: Optional[str] = None
    execution_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "request_id": str(self.request_id),
            "tool_id": self.tool_id,
            "state": self.state.value,
            "exit_code": self.exit_code,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "output_files": list(self.output_files.keys()),
            "artifacts_count": len(self.artifacts),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "execution_hash": self.execution_hash,
        }


class ToolImageRegistry:
    """Registry of approved tool container images."""

    # Approved tool images with their signatures
    APPROVED_IMAGES: Dict[str, Dict[str, Any]] = {
        "nmap": {
            "image": "frostgate/tools-nmap:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STANDARD,
            "network_required": True,
        },
        "masscan": {
            "image": "frostgate/tools-masscan:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STANDARD,
            "network_required": True,
        },
        "nikto": {
            "image": "frostgate/tools-nikto:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STANDARD,
            "network_required": True,
        },
        "nuclei": {
            "image": "frostgate/tools-nuclei:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STANDARD,
            "network_required": True,
        },
        "sqlmap": {
            "image": "frostgate/tools-sqlmap:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STRICT,
            "network_required": True,
        },
        "hashcat": {
            "image": "frostgate/tools-hashcat:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.MAXIMUM,
            "network_required": False,
        },
        "bloodhound": {
            "image": "frostgate/tools-bloodhound:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STRICT,
            "network_required": False,
        },
        "impacket": {
            "image": "frostgate/tools-impacket:latest",
            "digest": "sha256:placeholder",
            "isolation": IsolationLevel.STRICT,
            "network_required": True,
        },
    }

    @classmethod
    def get_image_config(cls, tool_id: str) -> Optional[Dict[str, Any]]:
        """Get approved image configuration for tool."""
        return cls.APPROVED_IMAGES.get(tool_id)

    @classmethod
    def is_approved(cls, tool_id: str) -> bool:
        """Check if tool has approved image."""
        return tool_id in cls.APPROVED_IMAGES

    @classmethod
    def get_isolation_level(cls, tool_id: str) -> IsolationLevel:
        """Get required isolation level for tool."""
        config = cls.APPROVED_IMAGES.get(tool_id)
        if config:
            return config.get("isolation", IsolationLevel.STANDARD)
        return IsolationLevel.MAXIMUM


class ToolExecutor:
    """
    Docker-isolated tool execution engine.

    Provides:
    - Sandboxed execution with resource limits
    - Network isolation and policies
    - Security hardening (seccomp, capabilities)
    - Input/output file handling
    - Execution logging and forensics
    - Container lifecycle management
    """

    def __init__(self, config: Config):
        """Initialize Tool Executor."""
        self.config = config
        self._docker_client = None
        self._active_containers: Dict[UUID, str] = {}
        self._execution_history: List[ToolExecutionResult] = []
        self._temp_dirs: Dict[UUID, Path] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start Tool Executor."""
        logger.info("Starting Tool Executor...")
        await self._initialize_docker()
        await self._setup_networks()
        logger.info("Tool Executor started")

    async def stop(self) -> None:
        """Stop Tool Executor and cleanup."""
        logger.info("Stopping Tool Executor...")

        # Terminate all active containers
        async with self._lock:
            for request_id, container_id in list(self._active_containers.items()):
                try:
                    await self._terminate_container(container_id)
                except Exception as e:
                    logger.error(f"Failed to terminate container {container_id}: {e}")

        # Cleanup temp directories
        for temp_dir in self._temp_dirs.values():
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                logger.error(f"Failed to cleanup temp dir {temp_dir}: {e}")

        # Close Docker client
        if self._docker_client:
            await self._close_docker()

        logger.info("Tool Executor stopped")

    async def _initialize_docker(self) -> None:
        """Initialize Docker client."""
        try:
            # Use docker SDK if available, otherwise use subprocess
            import docker
            self._docker_client = docker.from_env()
            logger.debug("Docker client initialized")
        except ImportError:
            logger.warning("Docker SDK not available, using subprocess mode")
            self._docker_client = None
        except Exception as e:
            logger.error(f"Failed to initialize Docker: {e}")
            self._docker_client = None

    async def _close_docker(self) -> None:
        """Close Docker client."""
        if self._docker_client:
            try:
                self._docker_client.close()
            except Exception:
                pass

    async def _setup_networks(self) -> None:
        """Setup isolated Docker networks."""
        if not self._docker_client:
            return

        try:
            # Check if sandbox network exists
            networks = self._docker_client.networks.list(names=["frostgate-sandbox-net"])
            if not networks:
                # Create isolated network
                self._docker_client.networks.create(
                    "frostgate-sandbox-net",
                    driver="bridge",
                    internal=True,  # No external connectivity
                    labels={"frostgate": "sandbox"},
                )
                logger.info("Created frostgate-sandbox-net network")
        except Exception as e:
            logger.warning(f"Could not setup sandbox network: {e}")

    async def execute(
        self,
        request: ToolExecutionRequest,
    ) -> ToolExecutionResult:
        """
        Execute tool in sandboxed container.

        Args:
            request: Tool execution request

        Returns:
            Execution result
        """
        started_at = datetime.utcnow()

        # Get or create sandbox config
        sandbox_config = request.sandbox_config
        if not sandbox_config:
            isolation = ToolImageRegistry.get_isolation_level(request.tool_id)
            sandbox_config = SandboxConfig.for_isolation_level(isolation)

        # Prepare result
        result = ToolExecutionResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            state=SandboxState.PENDING,
            exit_code=-1,
            stdout="",
            stderr="",
            started_at=started_at,
        )

        try:
            # Validate request
            await self._validate_request(request)

            # Setup workspace
            workspace = await self._setup_workspace(request)
            self._temp_dirs[request.request_id] = workspace

            # Execute in container
            result = await self._execute_in_container(
                request, sandbox_config, workspace
            )

            # Collect output files
            result.output_files = await self._collect_outputs(workspace)

            # Compute execution hash
            result.execution_hash = self._compute_execution_hash(request, result)

        except asyncio.TimeoutError:
            result.state = SandboxState.TIMEOUT
            result.stderr = f"Execution timed out after {sandbox_config.timeout_seconds}s"
            logger.warning(f"Tool execution timed out: {request.tool_id}")

        except SandboxError as e:
            result.state = SandboxState.FAILED
            result.stderr = str(e)
            logger.error(f"Sandbox error: {e}")

        except Exception as e:
            result.state = SandboxState.FAILED
            result.stderr = f"Unexpected error: {e}"
            logger.exception(f"Tool execution failed: {request.tool_id}")

        finally:
            result.completed_at = datetime.utcnow()
            result.duration_ms = int(
                (result.completed_at - started_at).total_seconds() * 1000
            )

            # Cleanup
            await self._cleanup_execution(request.request_id)

            # Log result
            self._execution_history.append(result)
            logger.info(
                f"Tool execution completed: {request.tool_id} "
                f"state={result.state.value} duration={result.duration_ms}ms"
            )

        return result

    async def _validate_request(self, request: ToolExecutionRequest) -> None:
        """Validate execution request."""
        # Check tool is approved
        if not ToolImageRegistry.is_approved(request.tool_id):
            # Allow custom images for testing
            if not request.tool_image:
                raise SandboxError(
                    f"Tool {request.tool_id} is not in approved registry",
                    tool_id=request.tool_id,
                )

        # Validate command
        if not request.command:
            raise SandboxError(
                "No command specified for execution",
                tool_id=request.tool_id,
            )

        # Check for dangerous commands
        dangerous_patterns = [
            "rm -rf /",
            ":(){ :|:& };:",  # Fork bomb
            "> /dev/sda",
            "dd if=/dev/zero",
        ]

        command_str = " ".join(request.command)
        for pattern in dangerous_patterns:
            if pattern in command_str:
                raise SandboxError(
                    f"Dangerous command pattern detected: {pattern}",
                    tool_id=request.tool_id,
                )

    async def _setup_workspace(self, request: ToolExecutionRequest) -> Path:
        """Setup isolated workspace for execution."""
        # Create temp directory
        workspace = Path(tempfile.mkdtemp(prefix=f"frostgate-{request.tool_id}-"))

        # Create subdirectories
        (workspace / "input").mkdir()
        (workspace / "output").mkdir()
        (workspace / "tmp").mkdir()

        # Write input files
        for filename, content in request.input_files.items():
            safe_filename = Path(filename).name  # Prevent path traversal
            filepath = workspace / "input" / safe_filename
            filepath.write_bytes(content)

        # Set restrictive permissions
        os.chmod(workspace, 0o700)

        return workspace

    async def _execute_in_container(
        self,
        request: ToolExecutionRequest,
        config: SandboxConfig,
        workspace: Path,
    ) -> ToolExecutionResult:
        """Execute tool in Docker container."""
        result = ToolExecutionResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            state=SandboxState.CREATING,
            exit_code=-1,
            stdout="",
            stderr="",
            started_at=datetime.utcnow(),
        )

        # Get image
        image_config = ToolImageRegistry.get_image_config(request.tool_id)
        image = request.tool_image or (image_config["image"] if image_config else f"alpine:latest")

        if self._docker_client:
            result = await self._execute_with_docker_sdk(
                request, config, workspace, image, result
            )
        else:
            result = await self._execute_with_subprocess(
                request, config, workspace, image, result
            )

        return result

    async def _execute_with_docker_sdk(
        self,
        request: ToolExecutionRequest,
        config: SandboxConfig,
        workspace: Path,
        image: str,
        result: ToolExecutionResult,
    ) -> ToolExecutionResult:
        """Execute using Docker SDK."""
        container = None

        try:
            # Build container config
            container_config = {
                "image": image,
                "command": request.command,
                "detach": True,
                "working_dir": config.working_dir,
                "environment": {
                    **config.environment,
                    **request.environment,
                    "FROSTGATE_REQUEST_ID": str(request.request_id),
                    "FROSTGATE_TOOL_ID": request.tool_id,
                },
                "volumes": {
                    str(workspace / "input"): {"bind": f"{config.working_dir}/input", "mode": "ro"},
                    str(workspace / "output"): {"bind": f"{config.working_dir}/output", "mode": "rw"},
                    str(workspace / "tmp"): {"bind": "/tmp", "mode": "rw"},
                },
                "labels": {
                    "frostgate.request_id": str(request.request_id),
                    "frostgate.tool_id": request.tool_id,
                    "frostgate.classification": request.classification_level,
                },
                **config.resource_limits.to_docker_config(),
                **config.network_policy.to_docker_config(),
                **config.security_policy.to_docker_config(),
            }

            # Create and start container
            result.state = SandboxState.CREATING
            container = self._docker_client.containers.create(**container_config)
            result.container_id = container.id

            async with self._lock:
                self._active_containers[request.request_id] = container.id

            result.state = SandboxState.RUNNING
            container.start()

            # Wait with timeout
            exit_result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, container.wait
                ),
                timeout=config.timeout_seconds,
            )

            result.exit_code = exit_result.get("StatusCode", -1)
            result.stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            result.stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            # Get resource usage
            try:
                stats = container.stats(stream=False)
                result.resource_usage = {
                    "cpu_percent": self._calculate_cpu_percent(stats),
                    "memory_usage_mb": stats.get("memory_stats", {}).get("usage", 0) / (1024 * 1024),
                }
            except Exception:
                pass

            result.state = SandboxState.COMPLETED if result.exit_code == 0 else SandboxState.FAILED

        except asyncio.TimeoutError:
            result.state = SandboxState.TIMEOUT
            if container:
                container.kill()
            raise

        finally:
            # Cleanup container
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

            async with self._lock:
                self._active_containers.pop(request.request_id, None)

        return result

    async def _execute_with_subprocess(
        self,
        request: ToolExecutionRequest,
        config: SandboxConfig,
        workspace: Path,
        image: str,
        result: ToolExecutionResult,
    ) -> ToolExecutionResult:
        """Execute using docker subprocess (fallback)."""
        # Build docker run command
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", f"frostgate-{request.request_id}",
            "--workdir", config.working_dir,
            "--read-only" if config.security_policy.read_only_rootfs else "",
            f"--memory={config.resource_limits.memory_mb}m",
            f"--cpus={config.resource_limits.cpu_cores}",
            f"--pids-limit={config.resource_limits.pids_limit}",
            "-v", f"{workspace}/input:{config.working_dir}/input:ro",
            "-v", f"{workspace}/output:{config.working_dir}/output:rw",
            "-v", f"{workspace}/tmp:/tmp:rw",
        ]

        # Add network config
        if not config.network_policy.enabled:
            docker_cmd.extend(["--network", "none"])

        # Add security config
        if config.security_policy.no_new_privileges:
            docker_cmd.append("--security-opt=no-new-privileges:true")

        if config.security_policy.drop_all_caps:
            docker_cmd.append("--cap-drop=ALL")

        # Add environment
        for key, value in {**config.environment, **request.environment}.items():
            docker_cmd.extend(["-e", f"{key}={value}"])

        # Add labels
        docker_cmd.extend(["--label", f"frostgate.request_id={request.request_id}"])
        docker_cmd.extend(["--label", f"frostgate.tool_id={request.tool_id}"])

        # Add image and command
        docker_cmd = [c for c in docker_cmd if c]  # Remove empty strings
        docker_cmd.append(image)
        docker_cmd.extend(request.command)

        result.state = SandboxState.RUNNING

        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async with self._lock:
                self._active_containers[request.request_id] = f"subprocess-{process.pid}"

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.timeout_seconds,
            )

            result.exit_code = process.returncode or 0
            result.stdout = stdout.decode("utf-8", errors="replace")
            result.stderr = stderr.decode("utf-8", errors="replace")
            result.state = SandboxState.COMPLETED if result.exit_code == 0 else SandboxState.FAILED

        except asyncio.TimeoutError:
            result.state = SandboxState.TIMEOUT
            process.kill()
            raise

        finally:
            async with self._lock:
                self._active_containers.pop(request.request_id, None)

        return result

    async def _terminate_container(self, container_id: str) -> None:
        """Terminate a running container."""
        if container_id.startswith("subprocess-"):
            # Kill subprocess
            pid = int(container_id.split("-")[1])
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        elif self._docker_client:
            try:
                container = self._docker_client.containers.get(container_id)
                container.kill()
                container.remove(force=True)
            except Exception:
                pass

    async def _collect_outputs(self, workspace: Path) -> Dict[str, bytes]:
        """Collect output files from workspace."""
        outputs = {}
        output_dir = workspace / "output"

        if output_dir.exists():
            for filepath in output_dir.rglob("*"):
                if filepath.is_file():
                    try:
                        relative_path = filepath.relative_to(output_dir)
                        outputs[str(relative_path)] = filepath.read_bytes()
                    except Exception as e:
                        logger.warning(f"Could not read output file {filepath}: {e}")

        return outputs

    async def _cleanup_execution(self, request_id: UUID) -> None:
        """Cleanup after execution."""
        # Remove from active containers
        async with self._lock:
            container_id = self._active_containers.pop(request_id, None)
            if container_id:
                await self._terminate_container(container_id)

        # Cleanup temp directory
        temp_dir = self._temp_dirs.pop(request_id, None)
        if temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def _compute_execution_hash(
        self,
        request: ToolExecutionRequest,
        result: ToolExecutionResult,
    ) -> str:
        """Compute hash of execution for forensics."""
        data = {
            "request_id": str(request.request_id),
            "tool_id": request.tool_id,
            "command": request.command,
            "arguments": request.arguments,
            "exit_code": result.exit_code,
            "stdout_hash": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_hash": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }

        content = json.dumps(data, sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def _calculate_cpu_percent(self, stats: Dict) -> float:
        """Calculate CPU percentage from stats."""
        try:
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                       stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]

            if system_delta > 0:
                return (cpu_delta / system_delta) * 100.0
        except (KeyError, TypeError):
            pass
        return 0.0

    async def terminate(self, request_id: UUID) -> bool:
        """Terminate a running execution."""
        async with self._lock:
            container_id = self._active_containers.get(request_id)

        if container_id:
            await self._terminate_container(container_id)
            logger.info(f"Terminated execution: {request_id}")
            return True

        return False

    def get_execution_history(
        self,
        limit: int = 100,
        tool_id: Optional[str] = None,
    ) -> List[ToolExecutionResult]:
        """Get execution history."""
        history = self._execution_history

        if tool_id:
            history = [r for r in history if r.tool_id == tool_id]

        return history[-limit:]

    def get_active_executions(self) -> Dict[UUID, str]:
        """Get currently active executions."""
        return self._active_containers.copy()


__all__ = [
    "ToolExecutor",
    "ToolExecutionRequest",
    "ToolExecutionResult",
    "SandboxConfig",
    "SandboxState",
    "IsolationLevel",
    "ResourceLimits",
    "NetworkPolicy",
    "SecurityPolicy",
    "ToolImageRegistry",
    "SandboxError",
]
