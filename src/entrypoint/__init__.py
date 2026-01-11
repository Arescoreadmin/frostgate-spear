"""
Entrypoint Controller - Blueprint v6.1 §3.2, §7

Multi-entrypoint management for realistic attack simulation.
Enforces diversity constraints and manages egress allocation.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class NetworkZone(Enum):
    """Network zone classifications."""
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    HYBRID = "HYBRID"
    TOR = "TOR"
    VPN = "VPN"


class EgressASNClass(Enum):
    """Provider egress ASN classifications."""
    RESIDENTIAL = "RESIDENTIAL"
    DATACENTER = "DATACENTER"
    MOBILE = "MOBILE"
    ENTERPRISE = "ENTERPRISE"


class EntrypointStatus(Enum):
    """Status of an entrypoint."""
    AVAILABLE = "AVAILABLE"
    ALLOCATED = "ALLOCATED"
    UNHEALTHY = "UNHEALTHY"
    MAINTENANCE = "MAINTENANCE"
    EXHAUSTED = "EXHAUSTED"


@dataclass
class EntrypointConstraints:
    """Constraints for an entrypoint."""
    max_concurrent_connections: int = 100
    rate_limit_rps: int = 50
    allowed_protocols: list[str] = field(default_factory=lambda: ["HTTP", "HTTPS", "TCP"])
    geo_restrictions: list[str] = field(default_factory=list)  # Country codes to avoid


@dataclass
class EntrypointSpec:
    """
    Entrypoint specification per Blueprint v6.1 §7.1.

    Fields:
    - entrypoint_id
    - region / pop
    - network_zone
    - egress_asn (or provider egress class)
    - egress_ip_pool_ref
    - constraints
    """
    entrypoint_id: str
    region: str
    pop: Optional[str]
    network_zone: NetworkZone
    egress_asn: Optional[str]
    egress_asn_class: EgressASNClass
    egress_ip_pool_ref: str
    constraints: EntrypointConstraints
    status: EntrypointStatus = EntrypointStatus.AVAILABLE
    health_check_enabled: bool = True
    health_check_interval_seconds: int = 30
    last_health_check: Optional[datetime] = None
    current_connections: int = 0


@dataclass
class DiversityRequirements:
    """
    Diversity requirements for entrypoints per Blueprint v6.1 §7.1.

    Policy enforced by OPA + entrypoint-controller:
    - Each entrypoint must be from different region OR different network zone OR different ASN class
    """
    require_different_regions: bool = False
    require_different_network_zones: bool = False
    require_different_asn_classes: bool = False
    minimum_unique_regions: int = 1
    minimum_unique_asns: int = 1


@dataclass
class EntrypointAllocation:
    """Allocation of an entrypoint to a campaign."""
    allocation_id: str
    entrypoint_id: str
    campaign_id: str
    tenant_id: str
    allocated_at: datetime
    expires_at: Optional[datetime]
    egress_ip: str
    evidence_hash: str  # Hash of allocation evidence


@dataclass
class EntrypointEvidence:
    """Evidence of entrypoint selection and egress identity."""
    evidence_id: str
    allocation_id: str
    entrypoint_id: str
    egress_ip: str
    egress_asn: str
    region: str
    network_zone: str
    timestamp: datetime
    signature: Optional[str] = None


class EntrypointController:
    """
    Entrypoint Controller per Blueprint v6.1 §3.2, §7.2.

    Responsibilities:
    - Allocates and pins execution to entrypoints
    - Emits evidence of entrypoint selection and egress identity
    - Enforces diversity at runtime (not just planning)
    """

    def __init__(self):
        self._entrypoints: dict[str, EntrypointSpec] = {}
        self._allocations: dict[str, EntrypointAllocation] = {}  # allocation_id -> allocation
        self._campaign_allocations: dict[str, list[str]] = {}  # campaign_id -> [allocation_ids]
        self._evidence_log: list[EntrypointEvidence] = []
        self._ip_pools: dict[str, list[str]] = {}  # pool_ref -> [IPs]

    def register_entrypoint(self, spec: EntrypointSpec) -> None:
        """Register a new entrypoint."""
        self._entrypoints[spec.entrypoint_id] = spec

    def register_ip_pool(self, pool_ref: str, ips: list[str]) -> None:
        """Register an IP pool for egress."""
        self._ip_pools[pool_ref] = ips

    def get_available_entrypoints(
        self,
        region: Optional[str] = None,
        network_zone: Optional[NetworkZone] = None,
        asn_class: Optional[EgressASNClass] = None,
    ) -> list[EntrypointSpec]:
        """Get available entrypoints matching criteria."""
        available = []
        for ep in self._entrypoints.values():
            if ep.status != EntrypointStatus.AVAILABLE:
                continue
            if region and ep.region != region:
                continue
            if network_zone and ep.network_zone != network_zone:
                continue
            if asn_class and ep.egress_asn_class != asn_class:
                continue
            available.append(ep)
        return available

    def validate_diversity(
        self,
        entrypoint_ids: list[str],
        requirements: DiversityRequirements,
    ) -> tuple[bool, list[str]]:
        """
        Validate that selected entrypoints meet diversity requirements.

        Per Blueprint v6.1 §7.1:
        - Each entrypoint must be from different region OR different network zone OR different ASN class
        """
        issues = []
        entrypoints = [self._entrypoints[eid] for eid in entrypoint_ids if eid in self._entrypoints]

        if not entrypoints:
            return False, ["No valid entrypoints found"]

        # Check region diversity
        if requirements.require_different_regions:
            regions = set(ep.region for ep in entrypoints)
            if len(regions) < len(entrypoints):
                issues.append("Not all entrypoints have different regions")

        if requirements.minimum_unique_regions > 1:
            regions = set(ep.region for ep in entrypoints)
            if len(regions) < requirements.minimum_unique_regions:
                issues.append(f"Need {requirements.minimum_unique_regions} unique regions, got {len(regions)}")

        # Check network zone diversity
        if requirements.require_different_network_zones:
            zones = set(ep.network_zone for ep in entrypoints)
            if len(zones) < len(entrypoints):
                issues.append("Not all entrypoints have different network zones")

        # Check ASN class diversity
        if requirements.require_different_asn_classes:
            asn_classes = set(ep.egress_asn_class for ep in entrypoints)
            if len(asn_classes) < len(entrypoints):
                issues.append("Not all entrypoints have different ASN classes")

        if requirements.minimum_unique_asns > 1:
            asns = set(ep.egress_asn or ep.egress_asn_class.value for ep in entrypoints)
            if len(asns) < requirements.minimum_unique_asns:
                issues.append(f"Need {requirements.minimum_unique_asns} unique ASNs, got {len(asns)}")

        return len(issues) == 0, issues

    def allocate_entrypoint(
        self,
        entrypoint_id: str,
        campaign_id: str,
        tenant_id: str,
        duration_seconds: Optional[int] = None,
    ) -> Optional[EntrypointAllocation]:
        """
        Allocate an entrypoint to a campaign.

        Per Blueprint v6.1 §7.2:
        - Allocates and pins execution to entrypoints
        - Emits evidence of entrypoint selection and egress identity
        """
        if entrypoint_id not in self._entrypoints:
            return None

        ep = self._entrypoints[entrypoint_id]
        if ep.status != EntrypointStatus.AVAILABLE:
            return None

        # Allocate IP from pool
        pool = self._ip_pools.get(ep.egress_ip_pool_ref, [])
        if not pool:
            return None

        egress_ip = pool[0]  # Simple allocation - production would be smarter

        allocation_id = f"alloc-{uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        # Create evidence hash
        evidence_data = {
            'allocation_id': allocation_id,
            'entrypoint_id': entrypoint_id,
            'campaign_id': campaign_id,
            'tenant_id': tenant_id,
            'egress_ip': egress_ip,
            'timestamp': now.isoformat()
        }
        evidence_hash = f"sha256:{hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest()}"

        allocation = EntrypointAllocation(
            allocation_id=allocation_id,
            entrypoint_id=entrypoint_id,
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            allocated_at=now,
            expires_at=datetime.fromtimestamp(
                now.timestamp() + duration_seconds, tz=timezone.utc
            ) if duration_seconds else None,
            egress_ip=egress_ip,
            evidence_hash=evidence_hash
        )

        self._allocations[allocation_id] = allocation

        if campaign_id not in self._campaign_allocations:
            self._campaign_allocations[campaign_id] = []
        self._campaign_allocations[campaign_id].append(allocation_id)

        # Update entrypoint status
        ep.status = EntrypointStatus.ALLOCATED
        ep.current_connections += 1

        # Emit evidence
        self._emit_evidence(allocation, ep)

        return allocation

    def _emit_evidence(self, allocation: EntrypointAllocation, ep: EntrypointSpec) -> None:
        """Emit evidence of entrypoint selection."""
        evidence = EntrypointEvidence(
            evidence_id=f"ev-{uuid4().hex[:16]}",
            allocation_id=allocation.allocation_id,
            entrypoint_id=ep.entrypoint_id,
            egress_ip=allocation.egress_ip,
            egress_asn=ep.egress_asn or ep.egress_asn_class.value,
            region=ep.region,
            network_zone=ep.network_zone.value,
            timestamp=datetime.now(timezone.utc)
        )
        self._evidence_log.append(evidence)

    def release_allocation(self, allocation_id: str) -> bool:
        """Release an entrypoint allocation."""
        if allocation_id not in self._allocations:
            return False

        allocation = self._allocations[allocation_id]
        ep = self._entrypoints.get(allocation.entrypoint_id)

        if ep:
            ep.current_connections = max(0, ep.current_connections - 1)
            if ep.current_connections == 0:
                ep.status = EntrypointStatus.AVAILABLE

        del self._allocations[allocation_id]

        if allocation.campaign_id in self._campaign_allocations:
            self._campaign_allocations[allocation.campaign_id].remove(allocation_id)

        return True

    def get_campaign_allocations(self, campaign_id: str) -> list[EntrypointAllocation]:
        """Get all allocations for a campaign."""
        allocation_ids = self._campaign_allocations.get(campaign_id, [])
        return [self._allocations[aid] for aid in allocation_ids if aid in self._allocations]

    def get_evidence_for_campaign(self, campaign_id: str) -> list[EntrypointEvidence]:
        """Get all entrypoint evidence for a campaign."""
        allocation_ids = set(self._campaign_allocations.get(campaign_id, []))
        return [e for e in self._evidence_log if e.allocation_id in allocation_ids]

    def check_entrypoint_health(self, entrypoint_id: str) -> bool:
        """Check health of an entrypoint."""
        if entrypoint_id not in self._entrypoints:
            return False

        ep = self._entrypoints[entrypoint_id]
        # In production, this would actually check connectivity
        ep.last_health_check = datetime.now(timezone.utc)
        return ep.status != EntrypointStatus.UNHEALTHY

    def preflight_check(
        self,
        requested_entrypoints: list[str],
        diversity_requirements: DiversityRequirements,
    ) -> dict:
        """
        Perform preflight check for entrypoint allocation.

        Per Blueprint v6.1 §7.1:
        - Preflight refuses campaigns that cannot meet diversity constraints
        """
        result = {
            'can_allocate': True,
            'issues': [],
            'warnings': [],
            'entrypoint_details': []
        }

        # Check all requested entrypoints exist and are available
        for eid in requested_entrypoints:
            if eid not in self._entrypoints:
                result['can_allocate'] = False
                result['issues'].append(f"Unknown entrypoint: {eid}")
                continue

            ep = self._entrypoints[eid]
            if ep.status != EntrypointStatus.AVAILABLE:
                result['can_allocate'] = False
                result['issues'].append(f"Entrypoint {eid} is {ep.status.value}")
                continue

            # Check IP pool
            if not self._ip_pools.get(ep.egress_ip_pool_ref):
                result['can_allocate'] = False
                result['issues'].append(f"No IPs available in pool for {eid}")
                continue

            result['entrypoint_details'].append({
                'entrypoint_id': eid,
                'region': ep.region,
                'network_zone': ep.network_zone.value,
                'egress_asn_class': ep.egress_asn_class.value,
                'available_ips': len(self._ip_pools.get(ep.egress_ip_pool_ref, []))
            })

        # Check diversity requirements
        if result['can_allocate']:
            is_diverse, diversity_issues = self.validate_diversity(
                requested_entrypoints,
                diversity_requirements
            )
            if not is_diverse:
                result['can_allocate'] = False
                result['issues'].extend(diversity_issues)

        return result

    def export_state(self) -> dict:
        """Export controller state for monitoring/debugging."""
        return {
            'entrypoints': {
                eid: {
                    'region': ep.region,
                    'network_zone': ep.network_zone.value,
                    'status': ep.status.value,
                    'current_connections': ep.current_connections
                }
                for eid, ep in self._entrypoints.items()
            },
            'active_allocations': len(self._allocations),
            'total_evidence_entries': len(self._evidence_log)
        }
