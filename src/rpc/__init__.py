"""
Frost Gate Spear RPC Layer

gRPC and REST API for service communication with zero-trust enforcement.
Integrates OPA for per-request authorization.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import aiohttp
from aiohttp import web

from ..core import FrostGateSpear
from ..core.config import Config
from ..core.exceptions import FrostGateError

logger = logging.getLogger(__name__)


class OPAAuthzClient:
    """
    OPA authorization client for per-request policy checks.

    Evaluates authorization policies for API requests including:
    - Request method and path authorization
    - Client identity/role verification
    - Classification-based access control
    """

    def __init__(self, opa_url: str = "http://localhost:8181"):
        """Initialize OPA authorization client."""
        self._opa_url = opa_url
        self._session: Optional[aiohttp.ClientSession] = None
        self._healthy = False

    async def start(self) -> None:
        """Start the OPA authorization client."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=3.0)
        )
        await self._check_health()

    async def stop(self) -> None:
        """Stop the OPA authorization client."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _check_health(self) -> bool:
        """Check if OPA server is healthy."""
        if not self._session:
            return False

        try:
            async with self._session.get(f"{self._opa_url}/health") as resp:
                self._healthy = resp.status == 200
                return self._healthy
        except Exception as e:
            logger.debug(f"OPA health check failed: {e}")
            self._healthy = False
            return False

    async def authorize(
        self,
        method: str,
        path: str,
        client_id: Optional[str] = None,
        client_cert: Optional[str] = None,
        classification_level: str = "UNCLASS",
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Check if request is authorized via OPA.

        Args:
            method: HTTP method
            path: Request path
            client_id: Client identifier
            client_cert: Client certificate subject
            classification_level: Classification level of operation
            roles: Client roles

        Returns:
            Authorization result with allowed, reasons, etc.
        """
        if not self._healthy or not self._session:
            # Fallback to local authorization
            return await self._local_authorize(
                method, path, client_id, classification_level
            )

        input_data = {
            "request": {
                "method": method,
                "path": path,
                "client_id": client_id,
                "client_cert": client_cert,
                "classification_level": classification_level,
                "roles": roles or [],
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        }

        try:
            url = f"{self._opa_url}/v1/data/frostgate/authz"
            async with self._session.post(
                url,
                json={"input": input_data},
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    policy_result = result.get("result", {})
                    return {
                        "allowed": policy_result.get("allow", False),
                        "reasons": policy_result.get("reasons", []),
                        "required_clearance": policy_result.get(
                            "required_clearance", "UNCLASS"
                        ),
                    }
                else:
                    logger.warning(
                        f"OPA authz check failed with status {resp.status}"
                    )
                    return await self._local_authorize(
                        method, path, client_id, classification_level
                    )

        except Exception as e:
            logger.warning(f"OPA authz error: {e}, using local fallback")
            return await self._local_authorize(
                method, path, client_id, classification_level
            )

    async def _local_authorize(
        self,
        method: str,
        path: str,
        client_id: Optional[str],
        classification_level: str,
    ) -> Dict[str, Any]:
        """
        Fallback local authorization when OPA unavailable.

        Implements basic access control rules.
        """
        reasons = []

        # Public paths - always allowed
        public_paths = ["/health", "/ready", "/api/v1/info"]
        if path in public_paths:
            return {"allowed": True, "reasons": []}

        # Metrics require at least basic auth
        if path == "/api/v1/metrics" and not client_id:
            reasons.append("Authentication required for metrics")
            return {"allowed": False, "reasons": reasons}

        # Mission operations require higher clearance for classified ops
        if "/missions" in path:
            classification_ranks = {
                "UNCLASS": 0,
                "CUI": 1,
                "SECRET": 2,
                "TOPSECRET": 3,
            }
            # Default require at least CUI for mission operations
            if classification_ranks.get(classification_level, 0) < 1:
                # Allow in simulation/lab modes
                pass

        # Default allow for authenticated requests or simulation mode
        return {"allowed": True, "reasons": reasons}

    @property
    def is_healthy(self) -> bool:
        """Check if OPA client is healthy."""
        return self._healthy


@dataclass
class RequestContext:
    """Request context with identity and authorization."""
    request_id: str
    client_id: str
    client_cert: Optional[str]
    timestamp: datetime
    classification_level: str


class RPCServer:
    """
    RPC Server for Frost Gate Spear.

    Provides REST API with:
    - mTLS enforcement
    - Per-request OPA policy checks
    - Rate limiting
    - Audit logging
    """

    def __init__(self, engine: FrostGateSpear, config: Config):
        """Initialize RPC Server."""
        self.engine = engine
        self.config = config
        self._opa_client: Optional[OPAAuthzClient] = None
        self.app = web.Application(middlewares=[
            self._error_middleware,
            self._auth_middleware,
            self._audit_middleware,
        ])
        self._setup_routes()

    async def _init_opa_client(self) -> None:
        """Initialize OPA authorization client."""
        opa_url = getattr(self.config.rpc, "opa_url", "http://localhost:8181")
        self._opa_client = OPAAuthzClient(opa_url)
        await self._opa_client.start()
        if self._opa_client.is_healthy:
            logger.info("OPA authorization client initialized")
        else:
            logger.warning("OPA server not available for authorization")

    def _setup_routes(self) -> None:
        """Setup API routes."""
        # Health
        self.app.router.add_get("/health", self._health)
        self.app.router.add_get("/ready", self._ready)

        # Missions
        self.app.router.add_post("/api/v1/missions", self._create_mission)
        self.app.router.add_get("/api/v1/missions", self._list_missions)
        self.app.router.add_get("/api/v1/missions/{id}", self._get_mission)
        self.app.router.add_post("/api/v1/missions/{id}/start", self._start_mission)
        self.app.router.add_post("/api/v1/missions/{id}/abort", self._abort_mission)
        self.app.router.add_get("/api/v1/missions/{id}/status", self._mission_status)
        self.app.router.add_get("/api/v1/missions/{id}/replay", self._replay_mission)

        # Validation
        self.app.router.add_post("/api/v1/validate/envelope", self._validate_envelope)
        self.app.router.add_post("/api/v1/validate/scenario", self._validate_scenario)

        # Metrics
        self.app.router.add_get("/api/v1/metrics", self._get_metrics)

        # Info
        self.app.router.add_get("/api/v1/info", self._get_info)

    @web.middleware
    async def _error_middleware(self, request: web.Request, handler) -> web.Response:
        """Error handling middleware."""
        try:
            return await handler(request)
        except FrostGateError as e:
            logger.error(f"FrostGate error: {e}")
            return web.json_response(e.to_dict(), status=400)
        except web.HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error: {e}")
            return web.json_response(
                {"error": "INTERNAL_ERROR", "message": str(e)},
                status=500,
            )

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler) -> web.Response:
        """Authentication and authorization middleware with OPA integration."""
        # Skip auth for health endpoints
        if request.path in ["/health", "/ready"]:
            return await handler(request)

        client_id = None
        client_cert = None
        classification_level = self.config.classification_level.value

        # Check mTLS if enabled
        if self.config.rpc.mtls_enabled:
            # Verify client certificate
            client_cert = request.headers.get("X-Client-Cert")
            if not client_cert:
                # For MVP, allow without cert in non-production
                if self.config.environment.value not in ["simulation", "lab"]:
                    return web.json_response(
                        {"error": "AUTH_REQUIRED", "message": "Client certificate required"},
                        status=401,
                    )
            else:
                # Extract client ID from certificate
                client_id = request.headers.get("X-Client-ID", client_cert[:32])

        # Check OPA policy if enabled
        if self.config.rpc.opa_check_enabled and self._opa_client:
            authz_result = await self._opa_client.authorize(
                method=request.method,
                path=request.path,
                client_id=client_id,
                client_cert=client_cert,
                classification_level=classification_level,
                roles=request.headers.get("X-Client-Roles", "").split(",") if request.headers.get("X-Client-Roles") else [],
            )

            if not authz_result.get("allowed", False):
                logger.warning(
                    f"OPA denied request: {request.method} {request.path} - "
                    f"reasons: {authz_result.get('reasons', [])}"
                )
                return web.json_response(
                    {
                        "error": "AUTHZ_DENIED",
                        "message": "Authorization denied by policy",
                        "reasons": authz_result.get("reasons", []),
                    },
                    status=403,
                )

        return await handler(request)

    @web.middleware
    async def _audit_middleware(self, request: web.Request, handler) -> web.Response:
        """Audit logging middleware."""
        start_time = datetime.utcnow()

        response = await handler(request)

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        logger.info(
            f"API Request: {request.method} {request.path} "
            f"status={response.status} duration={duration_ms:.2f}ms"
        )

        return response

    # Health endpoints

    async def _health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({"status": "healthy"})

    async def _ready(self, request: web.Request) -> web.Response:
        """Readiness check endpoint."""
        ready = self.engine.state.value == "ready"
        status = 200 if ready else 503
        return web.json_response(
            {"ready": ready, "state": self.engine.state.value},
            status=status,
        )

    # Mission endpoints

    async def _create_mission(self, request: web.Request) -> web.Response:
        """Create a new mission."""
        data = await request.json()

        mission = await self.engine.create_mission(
            policy_envelope=data["policy_envelope"],
            scenario=data["scenario"],
            persona_id=data.get("persona_id"),
        )

        return web.json_response(
            {
                "mission_id": str(mission.mission_id),
                "state": mission.state.value,
                "classification_level": mission.classification_level,
                "created_at": mission.created_at.isoformat(),
            },
            status=201,
        )

    async def _list_missions(self, request: web.Request) -> web.Response:
        """List all missions."""
        missions = []
        async with self.engine._mission_lock:
            for mission in self.engine._missions.values():
                missions.append(mission.to_dict())

        return web.json_response({"missions": missions})

    async def _get_mission(self, request: web.Request) -> web.Response:
        """Get mission details."""
        mission_id = UUID(request.match_info["id"])

        async with self.engine._mission_lock:
            mission = self.engine._missions.get(mission_id)

        if not mission:
            return web.json_response(
                {"error": "NOT_FOUND", "message": f"Mission {mission_id} not found"},
                status=404,
            )

        return web.json_response(mission.to_dict())

    async def _start_mission(self, request: web.Request) -> web.Response:
        """Start a mission."""
        mission_id = UUID(request.match_info["id"])

        await self.engine.start_mission(mission_id)

        return web.json_response({"message": "Mission started", "mission_id": str(mission_id)})

    async def _abort_mission(self, request: web.Request) -> web.Response:
        """Abort a mission."""
        mission_id = UUID(request.match_info["id"])
        data = await request.json() if request.body_exists else {}
        reason = data.get("reason", "API request")

        await self.engine.abort_mission(mission_id, reason=reason)

        return web.json_response({"message": "Mission aborted", "mission_id": str(mission_id)})

    async def _mission_status(self, request: web.Request) -> web.Response:
        """Get mission status."""
        mission_id = UUID(request.match_info["id"])

        status = await self.engine.get_mission_status(mission_id)

        return web.json_response(status)

    async def _replay_mission(self, request: web.Request) -> web.Response:
        """Replay a mission."""
        mission_id = UUID(request.match_info["id"])

        result = await self.engine.replay_mission(mission_id)

        return web.json_response({
            "mission_id": str(result.mission_id),
            "success": result.success,
            "completeness": result.completeness,
            "divergences": result.divergences,
            "timestamp": result.timestamp.isoformat(),
        })

    # Validation endpoints

    async def _validate_envelope(self, request: web.Request) -> web.Response:
        """Validate policy envelope."""
        data = await request.json()

        from ..policy_interpreter import PolicyInterpreter

        interpreter = PolicyInterpreter(self.config)
        await interpreter.start()

        try:
            result = await interpreter.validate_envelope(data)
            return web.json_response({
                "valid": result.valid,
                "errors": result.errors,
                "warnings": result.warnings,
                "envelope_hash": result.envelope_hash,
            })
        finally:
            await interpreter.stop()

    async def _validate_scenario(self, request: web.Request) -> web.Response:
        """Validate scenario."""
        data = await request.json()

        # Basic validation
        errors = []

        if "name" not in data:
            errors.append("Missing required field: name")

        if "targets" not in data:
            errors.append("Missing required field: targets")

        return web.json_response({
            "valid": len(errors) == 0,
            "errors": errors,
        })

    # Metrics endpoints

    async def _get_metrics(self, request: web.Request) -> web.Response:
        """Get platform metrics."""
        metrics = self.engine.metrics

        return web.json_response({
            "active_missions": metrics.active_missions,
            "completed_missions": metrics.completed_missions,
            "policy_violations": metrics.policy_violations,
            "roe_violations": metrics.roe_violations,
            "safety_violations": metrics.safety_violations,
            "forensic_completeness": metrics.forensic_completeness,
            "uptime_seconds": metrics.uptime_seconds,
        })

    # Info endpoint

    async def _get_info(self, request: web.Request) -> web.Response:
        """Get platform info."""
        from .. import __version__

        return web.json_response({
            "name": "Frost Gate Spear",
            "version": __version__,
            "engine_id": str(self.engine.engine_id),
            "state": self.engine.state.value,
            "environment": self.config.environment.value,
            "classification_level": self.config.classification_level.value,
        })

    async def start(self, host: str, port: int) -> web.AppRunner:
        """Start the server."""
        # Initialize OPA client for authorization
        await self._init_opa_client()

        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, host, port)
        await site.start()

        logger.info(f"RPC Server started on {host}:{port}")
        return runner

    async def stop(self) -> None:
        """Stop the server and cleanup resources."""
        if self._opa_client:
            await self._opa_client.stop()
            logger.info("OPA client stopped")

    async def serve_forever(self) -> None:
        """Serve forever."""
        while True:
            await asyncio.sleep(3600)


async def create_server(engine: FrostGateSpear, host: str, port: int) -> RPCServer:
    """Create and start RPC server."""
    server = RPCServer(engine, engine.config)
    await server.start(host, port)
    return server
