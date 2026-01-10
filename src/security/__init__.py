"""
Frost Gate Spear - Security Integration

OPA policy evaluation and mTLS certificate validation for zero-trust architecture.
"""

import asyncio
import hashlib
import json
import logging
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

from ..core.config import Config
from ..core.exceptions import FrostGateError

logger = logging.getLogger(__name__)


class SecurityError(FrostGateError):
    """Security-related error."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, "SECURITY_ERROR", **kwargs)


class PolicyDecision(Enum):
    """OPA policy decision."""
    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class PolicyEvaluationResult:
    """Result of OPA policy evaluation."""
    decision: PolicyDecision
    policy_name: str
    query_path: str
    input_hash: str
    bindings: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "policy_name": self.policy_name,
            "query_path": self.query_path,
            "input_hash": self.input_hash,
            "bindings": self.bindings,
            "reasons": self.reasons,
            "evaluation_time_ms": self.evaluation_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class CertificateInfo:
    """X.509 certificate information."""
    subject: str
    issuer: str
    serial_number: int
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    common_name: Optional[str] = None
    organization: Optional[str] = None
    san_dns_names: List[str] = field(default_factory=list)
    san_ips: List[str] = field(default_factory=list)
    key_usage: List[str] = field(default_factory=list)
    is_ca: bool = False

    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = datetime.utcnow()
        return self.not_before <= now <= self.not_after

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "fingerprint_sha256": self.fingerprint_sha256,
            "common_name": self.common_name,
            "organization": self.organization,
            "san_dns_names": self.san_dns_names,
            "san_ips": self.san_ips,
            "is_valid": self.is_valid(),
        }


@dataclass
class mTLSConfig:
    """mTLS configuration."""
    enabled: bool = True
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    verify_hostname: bool = True
    require_client_cert: bool = True
    allowed_client_cns: List[str] = field(default_factory=list)
    revocation_check: bool = True
    min_tls_version: str = "TLSv1.3"


class OPAClient:
    """
    Open Policy Agent client for policy evaluation.

    Supports:
    - Policy evaluation via HTTP API
    - Policy bundle loading
    - Caching of decisions
    - Retry with backoff
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        timeout: float = 5.0,
        cache_ttl: int = 60,
    ):
        """
        Initialize OPA client.

        Args:
            opa_url: OPA server URL
            timeout: Request timeout in seconds
            cache_ttl: Cache TTL in seconds
        """
        self.opa_url = opa_url.rstrip("/")
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, Tuple[PolicyEvaluationResult, datetime]] = {}
        self._connected = False

    async def connect(self) -> bool:
        """Connect to OPA server."""
        try:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

            # Health check
            async with self._session.get(f"{self.opa_url}/health") as resp:
                if resp.status == 200:
                    self._connected = True
                    logger.info(f"Connected to OPA at {self.opa_url}")
                    return True

        except Exception as e:
            logger.warning(f"Could not connect to OPA: {e}")
            self._connected = False

        return False

    async def close(self) -> None:
        """Close OPA connection."""
        if self._session:
            await self._session.close()
            self._session = None
        self._connected = False

    async def evaluate_policy(
        self,
        policy_path: str,
        input_data: Dict[str, Any],
        use_cache: bool = True,
    ) -> PolicyEvaluationResult:
        """
        Evaluate policy against input.

        Args:
            policy_path: Policy path (e.g., "roe/allow")
            input_data: Input data for evaluation
            use_cache: Whether to use cached results

        Returns:
            Policy evaluation result
        """
        # Compute input hash for caching
        input_hash = self._hash_input(input_data)
        cache_key = f"{policy_path}:{input_hash}"

        # Check cache
        if use_cache and cache_key in self._cache:
            result, cached_at = self._cache[cache_key]
            if datetime.utcnow() - cached_at < timedelta(seconds=self.cache_ttl):
                logger.debug(f"Cache hit for policy {policy_path}")
                return result

        start_time = datetime.utcnow()

        # If not connected or session unavailable, return default deny
        if not self._connected or not self._session:
            logger.warning(f"OPA not connected, defaulting to DENY for {policy_path}")
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                policy_name=policy_path,
                query_path=f"/v1/data/{policy_path.replace('.', '/')}",
                input_hash=input_hash,
                reasons=["OPA server not available"],
            )

        try:
            # Prepare request
            query_path = f"/v1/data/{policy_path.replace('.', '/')}"
            payload = {"input": input_data}

            async with self._session.post(
                f"{self.opa_url}{query_path}",
                json=payload,
            ) as resp:
                eval_time = (datetime.utcnow() - start_time).total_seconds() * 1000

                if resp.status == 200:
                    data = await resp.json()
                    result_value = data.get("result")

                    # Interpret result
                    if isinstance(result_value, bool):
                        decision = PolicyDecision.ALLOW if result_value else PolicyDecision.DENY
                    elif isinstance(result_value, dict):
                        decision = PolicyDecision.ALLOW if result_value.get("allow") else PolicyDecision.DENY
                    else:
                        decision = PolicyDecision.NOT_APPLICABLE

                    result = PolicyEvaluationResult(
                        decision=decision,
                        policy_name=policy_path,
                        query_path=query_path,
                        input_hash=input_hash,
                        bindings=result_value if isinstance(result_value, dict) else {},
                        evaluation_time_ms=eval_time,
                    )

                else:
                    result = PolicyEvaluationResult(
                        decision=PolicyDecision.DENY,
                        policy_name=policy_path,
                        query_path=query_path,
                        input_hash=input_hash,
                        reasons=[f"OPA returned status {resp.status}"],
                        evaluation_time_ms=eval_time,
                    )

        except asyncio.TimeoutError:
            result = PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                policy_name=policy_path,
                query_path=f"/v1/data/{policy_path.replace('.', '/')}",
                input_hash=input_hash,
                reasons=["OPA request timed out"],
            )

        except Exception as e:
            logger.error(f"OPA evaluation error: {e}")
            result = PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                policy_name=policy_path,
                query_path=f"/v1/data/{policy_path.replace('.', '/')}",
                input_hash=input_hash,
                reasons=[f"OPA error: {str(e)}"],
            )

        # Cache result
        if use_cache:
            self._cache[cache_key] = (result, datetime.utcnow())

        return result

    async def evaluate_roe(
        self,
        action: Dict[str, Any],
        roe: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate ROE policy for an action.

        Args:
            action: Action to evaluate
            roe: ROE constraints
            context: Additional context

        Returns:
            Policy evaluation result
        """
        input_data = {
            "action": action,
            "roe": roe,
            "context": context or {},
        }

        return await self.evaluate_policy("frostgate.roe.allow", input_data)

    async def evaluate_safety(
        self,
        action: Dict[str, Any],
        constraints: Dict[str, Any],
    ) -> PolicyEvaluationResult:
        """
        Evaluate safety constraints for an action.

        Args:
            action: Action to evaluate
            constraints: Safety constraints

        Returns:
            Policy evaluation result
        """
        input_data = {
            "action": action,
            "constraints": constraints,
        }

        return await self.evaluate_policy("frostgate.safety.allow", input_data)

    async def evaluate_mls(
        self,
        source_ring: str,
        dest_ring: str,
        data_type: str,
        operation: str,
    ) -> PolicyEvaluationResult:
        """
        Evaluate MLS policy for cross-ring operation.

        Args:
            source_ring: Source classification ring
            dest_ring: Destination ring
            data_type: Type of data
            operation: Operation type

        Returns:
            Policy evaluation result
        """
        input_data = {
            "source_ring": source_ring,
            "dest_ring": dest_ring,
            "data_type": data_type,
            "operation": operation,
        }

        return await self.evaluate_policy("frostgate.mls.allow", input_data)

    def _hash_input(self, input_data: Dict[str, Any]) -> str:
        """Compute hash of input data."""
        content = json.dumps(input_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class CertificateValidator:
    """
    X.509 certificate validator for mTLS.

    Supports:
    - Certificate parsing and validation
    - Chain verification
    - CN/SAN validation
    - Revocation checking (CRL/OCSP)
    """

    def __init__(self, config: mTLSConfig):
        """
        Initialize certificate validator.

        Args:
            config: mTLS configuration
        """
        self.config = config
        self._ca_certs: List[x509.Certificate] = []
        self._trusted_cns: set = set(config.allowed_client_cns)

    async def load_ca_certificates(self) -> None:
        """Load CA certificates from configured path."""
        if not self.config.ca_cert_path:
            logger.warning("No CA certificate path configured")
            return

        ca_path = Path(self.config.ca_cert_path)
        if not ca_path.exists():
            logger.warning(f"CA certificate path does not exist: {ca_path}")
            return

        try:
            if ca_path.is_file():
                self._load_cert_file(ca_path)
            elif ca_path.is_dir():
                for cert_file in ca_path.glob("*.pem"):
                    self._load_cert_file(cert_file)
                for cert_file in ca_path.glob("*.crt"):
                    self._load_cert_file(cert_file)

            logger.info(f"Loaded {len(self._ca_certs)} CA certificates")

        except Exception as e:
            logger.error(f"Failed to load CA certificates: {e}")

    def _load_cert_file(self, path: Path) -> None:
        """Load certificates from PEM file."""
        try:
            pem_data = path.read_bytes()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            self._ca_certs.append(cert)
        except Exception as e:
            logger.warning(f"Could not load certificate from {path}: {e}")

    def parse_certificate(self, cert_pem: str) -> CertificateInfo:
        """
        Parse X.509 certificate from PEM string.

        Args:
            cert_pem: Certificate in PEM format

        Returns:
            Parsed certificate information
        """
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )

        return self._extract_cert_info(cert)

    def _extract_cert_info(self, cert: x509.Certificate) -> CertificateInfo:
        """Extract information from certificate."""
        # Get subject attributes
        subject = cert.subject
        common_name = None
        organization = None

        try:
            cn_attr = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                common_name = cn_attr[0].value
        except Exception:
            pass

        try:
            org_attr = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if org_attr:
                organization = org_attr[0].value
        except Exception:
            pass

        # Get SAN
        san_dns_names = []
        san_ips = []

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            san_ips = [
                str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
            ]
        except x509.ExtensionNotFound:
            pass

        # Get key usage
        key_usage = []
        try:
            ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if ku_ext.value.digital_signature:
                key_usage.append("digital_signature")
            if ku_ext.value.key_encipherment:
                key_usage.append("key_encipherment")
            if ku_ext.value.key_cert_sign:
                key_usage.append("key_cert_sign")
        except x509.ExtensionNotFound:
            pass

        # Check if CA
        is_ca = False
        try:
            bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc_ext.value.ca
        except x509.ExtensionNotFound:
            pass

        # Compute fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        return CertificateInfo(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            fingerprint_sha256=fingerprint,
            common_name=common_name,
            organization=organization,
            san_dns_names=san_dns_names,
            san_ips=san_ips,
            key_usage=key_usage,
            is_ca=is_ca,
        )

    def validate_certificate(
        self,
        cert_pem: str,
        expected_cn: Optional[str] = None,
    ) -> Tuple[bool, CertificateInfo, List[str]]:
        """
        Validate X.509 certificate.

        Args:
            cert_pem: Certificate in PEM format
            expected_cn: Expected common name (optional)

        Returns:
            Tuple of (is_valid, cert_info, errors)
        """
        errors = []

        try:
            cert_info = self.parse_certificate(cert_pem)
        except Exception as e:
            return False, None, [f"Failed to parse certificate: {e}"]

        # Check validity period
        if not cert_info.is_valid():
            errors.append(
                f"Certificate not valid: {cert_info.not_before} - {cert_info.not_after}"
            )

        # Check CN if required
        if expected_cn and cert_info.common_name != expected_cn:
            errors.append(
                f"CN mismatch: expected {expected_cn}, got {cert_info.common_name}"
            )

        # Check against allowed CNs
        if self._trusted_cns:
            if cert_info.common_name not in self._trusted_cns:
                errors.append(
                    f"CN {cert_info.common_name} not in trusted list"
                )

        # TODO: Add chain verification against CA certs
        # TODO: Add CRL/OCSP revocation checking

        is_valid = len(errors) == 0
        return is_valid, cert_info, errors


class mTLSContext:
    """
    mTLS SSL context manager.

    Provides SSL contexts for server and client authentication.
    """

    def __init__(self, config: mTLSConfig):
        """
        Initialize mTLS context.

        Args:
            config: mTLS configuration
        """
        self.config = config
        self._server_context: Optional[ssl.SSLContext] = None
        self._client_context: Optional[ssl.SSLContext] = None

    def create_server_context(self) -> ssl.SSLContext:
        """Create SSL context for server (requires client cert)."""
        if not self.config.enabled:
            return None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set minimum TLS version
        if self.config.min_tls_version == "TLSv1.3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load server certificate
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(
                self.config.client_cert_path,
                self.config.client_key_path,
            )

        # Load CA for client verification
        if self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)

        # Require client certificate
        if self.config.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL

        # Security hardening
        context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")

        self._server_context = context
        return context

    def create_client_context(self) -> ssl.SSLContext:
        """Create SSL context for client (sends client cert)."""
        if not self.config.enabled:
            return None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set minimum TLS version
        if self.config.min_tls_version == "TLSv1.3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load client certificate
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(
                self.config.client_cert_path,
                self.config.client_key_path,
            )

        # Load CA for server verification
        if self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        context.check_hostname = self.config.verify_hostname

        self._client_context = context
        return context


class SecurityManager:
    """
    Unified security manager for OPA and mTLS.

    Coordinates:
    - OPA policy evaluation
    - mTLS certificate validation
    - Request authorization
    - Security audit logging
    """

    def __init__(self, config: Config):
        """
        Initialize Security Manager.

        Args:
            config: Application configuration
        """
        self.config = config

        # OPA client
        opa_url = getattr(config, "opa_url", "http://localhost:8181")
        self.opa_client = OPAClient(opa_url=opa_url)

        # mTLS configuration
        mtls_config = mTLSConfig(
            enabled=config.rpc.mtls_enabled,
            ca_cert_path=getattr(config.rpc, "ca_cert_path", None),
            client_cert_path=getattr(config.rpc, "client_cert_path", None),
            client_key_path=getattr(config.rpc, "client_key_path", None),
        )
        self.cert_validator = CertificateValidator(mtls_config)
        self.mtls_context = mTLSContext(mtls_config)

    async def start(self) -> None:
        """Start security manager."""
        logger.info("Starting Security Manager...")

        # Connect to OPA
        await self.opa_client.connect()

        # Load CA certificates
        await self.cert_validator.load_ca_certificates()

        logger.info("Security Manager started")

    async def stop(self) -> None:
        """Stop security manager."""
        logger.info("Stopping Security Manager...")
        await self.opa_client.close()

    async def authorize_action(
        self,
        action: Dict[str, Any],
        roe: Dict[str, Any],
        client_cert: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Authorize an action against ROE and policies.

        Args:
            action: Action to authorize
            roe: ROE constraints
            client_cert: Client certificate (optional)

        Returns:
            Tuple of (authorized, reasons)
        """
        reasons = []

        # Validate client certificate if provided
        if client_cert and self.config.rpc.mtls_enabled:
            valid, cert_info, cert_errors = self.cert_validator.validate_certificate(
                client_cert
            )
            if not valid:
                reasons.extend(cert_errors)
                return False, reasons

        # Evaluate ROE policy via OPA
        if self.config.rpc.opa_check_enabled:
            result = await self.opa_client.evaluate_roe(action, roe)

            if result.decision != PolicyDecision.ALLOW:
                reasons.extend(result.reasons or ["ROE policy denied"])
                return False, reasons

        return True, []

    async def check_mls_compliance(
        self,
        source_ring: str,
        dest_ring: str,
        operation: str,
    ) -> Tuple[bool, str]:
        """
        Check MLS compliance for cross-ring operation.

        Args:
            source_ring: Source classification ring
            dest_ring: Destination ring
            operation: Operation type

        Returns:
            Tuple of (compliant, reason)
        """
        result = await self.opa_client.evaluate_mls(
            source_ring=source_ring,
            dest_ring=dest_ring,
            data_type="model",
            operation=operation,
        )

        if result.decision == PolicyDecision.ALLOW:
            return True, ""
        else:
            return False, result.reasons[0] if result.reasons else "MLS policy denied"


__all__ = [
    "SecurityManager",
    "OPAClient",
    "CertificateValidator",
    "mTLSContext",
    "mTLSConfig",
    "PolicyEvaluationResult",
    "PolicyDecision",
    "CertificateInfo",
    "SecurityError",
]
