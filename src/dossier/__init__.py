"""
Dossier Service - Blueprint v6.1 §0, §3.1, §4.2.8

Audit-grade dossier assembly with disclosure controls and ZK integration.
Provides one-click audit-grade dossier generation per WTF Operator Experience.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class DossierType(Enum):
    """Types of dossiers that can be generated."""
    FULL = "FULL"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_DETAIL = "TECHNICAL_DETAIL"
    COMPLIANCE = "COMPLIANCE"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"


class TemplateType(Enum):
    """Template types per Blueprint v6.1 §4.2.8."""
    AUDITOR_TEMPLATE = "AUDITOR_TEMPLATE"
    OPERATOR_TEMPLATE = "OPERATOR_TEMPLATE"
    CUSTOMER_TEMPLATE = "CUSTOMER_TEMPLATE"
    REGULATORY_TEMPLATE = "REGULATORY_TEMPLATE"


class EmbargoType(Enum):
    """Embargo types for disclosure control."""
    NONE = "NONE"
    TIME_BASED = "TIME_BASED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    COORDINATED_DISCLOSURE = "COORDINATED_DISCLOSURE"


class FindingSeverity(Enum):
    """Finding severity levels."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """A security finding."""
    finding_id: str
    severity: FindingSeverity
    category: str
    title: str
    description: str
    affected_assets: list[str]
    cve_refs: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    evidence_refs: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    credential_mode: str = "UNAUTHENTICATED"  # Which mode discovered this


@dataclass
class DossierSection:
    """A section within a dossier."""
    section_id: str
    title: str
    section_type: str
    content: str
    content_hash: str
    page_range: Optional[tuple[int, int]] = None
    classification_level: str = "UNCLASS"
    redaction_applied: bool = False


@dataclass
class ZKAttestation:
    """Zero-knowledge attestation reference."""
    attestation_id: str
    attestation_type: str
    proof_hash: str
    proof_system: str
    verification_key_ref: str
    public_inputs_hash: str


@dataclass
class DisclosureEmbargoPolicy:
    """Disclosure embargo policy per Blueprint v6.1 §4.2.8."""
    policy_id: str
    embargo_type: EmbargoType
    embargo_until: Optional[datetime] = None
    disclosure_approvers: list[str] = field(default_factory=list)
    coordinated_parties: list[dict] = field(default_factory=list)


@dataclass
class CredentialModeComparison:
    """Comparison of findings between credential modes per Blueprint v6.1 §7.4."""
    unauthenticated: dict
    authenticated: dict
    delta_analysis: dict


@dataclass
class DossierManifest:
    """
    Complete dossier manifest per Blueprint v6.1 §4.2.8.

    Includes:
    - auditor_template vs operator_template
    - zk_attestation_refs[]
    - disclosure_embargo_policy_ref
    - verifier pack reference for customer validation
    """
    dossier_id: str
    version: str
    campaign_id: str
    tenant_id: str
    created_at: datetime
    dossier_type: DossierType
    template_type: TemplateType
    classification_level: str
    sections: list[DossierSection]
    findings_summary: dict
    credential_mode_comparison: Optional[CredentialModeComparison]
    evidence_bundle_refs: list[dict]
    zk_attestation_refs: list[ZKAttestation]
    disclosure_embargo_policy: DisclosureEmbargoPolicy
    verifier_pack_ref: dict
    integrity: dict
    generation_metadata: dict
    signature: Optional[dict] = None
    witness_signature: Optional[dict] = None


class DossierService:
    """
    Dossier Builder Service per Blueprint v6.1 §0, §3.1.

    Per Blueprint v6.1 §0 (WTF Operator Experience):
    - One-click audit-grade dossier
    - Optional ZK attestations
    - Embargo workflow

    Per Blueprint v6.1 §7.4:
    - Dossier compares findings between credential modes
    """

    VERIFIER_PACK_VERSION = "1.0.0"

    def __init__(self, service_id: str):
        self.service_id = service_id
        self._dossiers: dict[str, DossierManifest] = {}
        self._templates: dict[TemplateType, dict] = self._load_default_templates()

    def _load_default_templates(self) -> dict[TemplateType, dict]:
        """Load default dossier templates."""
        return {
            TemplateType.AUDITOR_TEMPLATE: {
                'sections': [
                    'EXECUTIVE_SUMMARY',
                    'SCOPE_DEFINITION',
                    'METHODOLOGY',
                    'FINDINGS',
                    'EVIDENCE_SUMMARY',
                    'RECOMMENDATIONS',
                    'ATTESTATIONS',
                    'APPENDIX'
                ],
                'include_raw_evidence': True,
                'include_technical_details': True
            },
            TemplateType.OPERATOR_TEMPLATE: {
                'sections': [
                    'EXECUTIVE_SUMMARY',
                    'SCOPE_DEFINITION',
                    'FINDINGS',
                    'RECOMMENDATIONS'
                ],
                'include_raw_evidence': False,
                'include_technical_details': False
            },
            TemplateType.CUSTOMER_TEMPLATE: {
                'sections': [
                    'EXECUTIVE_SUMMARY',
                    'SCOPE_DEFINITION',
                    'FINDINGS',
                    'CREDENTIAL_MODE_COMPARISON',
                    'RECOMMENDATIONS',
                    'ATTESTATIONS'
                ],
                'include_raw_evidence': False,
                'include_technical_details': True
            },
            TemplateType.REGULATORY_TEMPLATE: {
                'sections': [
                    'EXECUTIVE_SUMMARY',
                    'SCOPE_DEFINITION',
                    'METHODOLOGY',
                    'FINDINGS',
                    'EVIDENCE_SUMMARY',
                    'RECOMMENDATIONS',
                    'ATTESTATIONS',
                    'APPENDIX'
                ],
                'include_raw_evidence': True,
                'include_technical_details': True,
                'require_zk_attestations': True
            }
        }

    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def _compute_merkle_root(self, hashes: list[str]) -> str:
        """Compute merkle root from list of hashes."""
        if not hashes:
            return self._compute_hash("")

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])

            new_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_level.append(self._compute_hash(combined))
            hashes = new_level

        return hashes[0]

    def create_finding_summary(self, findings: list[Finding]) -> dict:
        """Create findings summary for dossier."""
        by_severity = {s.value: 0 for s in FindingSeverity}
        by_category: dict[str, int] = {}

        for finding in findings:
            by_severity[finding.severity.value] += 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

        return {
            'total_findings': len(findings),
            'by_severity': by_severity,
            'by_category': by_category,
            'remediation_status': {
                'open': len(findings),
                'in_progress': 0,
                'resolved': 0,
                'accepted_risk': 0
            }
        }

    def create_credential_mode_comparison(
        self,
        unauth_findings: list[Finding],
        auth_findings: list[Finding],
        unauth_cost: float,
        auth_cost: float,
    ) -> CredentialModeComparison:
        """
        Create credential mode comparison per Blueprint v6.1 §7.4.

        Compares findings between credential modes including coverage/cost/evidence deltas.
        """
        # Calculate unique findings in each mode
        unauth_ids = {f.finding_id for f in unauth_findings}
        auth_ids = {f.finding_id for f in auth_findings}

        additional_with_auth = len(auth_ids - unauth_ids)
        total_unique = len(unauth_ids | auth_ids)

        unauth_coverage = len(unauth_ids) / total_unique * 100 if total_unique > 0 else 0
        auth_coverage = len(auth_ids) / total_unique * 100 if total_unique > 0 else 0

        return CredentialModeComparison(
            unauthenticated={
                'findings_count': len(unauth_findings),
                'coverage_percentage': round(unauth_coverage, 2),
                'cost_usd': unauth_cost
            },
            authenticated={
                'findings_count': len(auth_findings),
                'coverage_percentage': round(auth_coverage, 2),
                'cost_usd': auth_cost
            },
            delta_analysis={
                'additional_findings_with_auth': additional_with_auth,
                'coverage_improvement': round(auth_coverage - unauth_coverage, 2),
                'cost_difference': round(auth_cost - unauth_cost, 2)
            }
        )

    def create_section(
        self,
        section_type: str,
        title: str,
        content: str,
        classification_level: str = "UNCLASS",
    ) -> DossierSection:
        """Create a dossier section."""
        return DossierSection(
            section_id=f"sec-{uuid4().hex[:12]}",
            title=title,
            section_type=section_type,
            content=content,
            content_hash=self._compute_hash(content),
            classification_level=classification_level
        )

    def create_zk_attestation(
        self,
        attestation_type: str,
        proof_data: bytes,
        public_inputs: dict,
        proof_system: str = "GROTH16",
    ) -> ZKAttestation:
        """Create a ZK attestation reference."""
        return ZKAttestation(
            attestation_id=f"zk-{uuid4().hex[:16]}",
            attestation_type=attestation_type,
            proof_hash=self._compute_hash(proof_data),
            proof_system=proof_system,
            verification_key_ref=f"vk-{attestation_type.lower()}",
            public_inputs_hash=self._compute_hash(public_inputs)
        )

    def generate_dossier(
        self,
        campaign_id: str,
        tenant_id: str,
        dossier_type: DossierType,
        template_type: TemplateType,
        findings: list[Finding],
        evidence_bundle_refs: list[dict],
        classification_level: str = "UNCLASS",
        embargo_policy: Optional[DisclosureEmbargoPolicy] = None,
        credential_mode_comparison: Optional[CredentialModeComparison] = None,
        zk_attestations: Optional[list[ZKAttestation]] = None,
    ) -> DossierManifest:
        """
        Generate a complete audit-grade dossier.

        Per Blueprint v6.1 §0:
        - One-click audit-grade dossier
        - Optional ZK attestations
        - Embargo workflow
        """
        dossier_id = f"dossier-{uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        template = self._templates.get(template_type, self._templates[TemplateType.OPERATOR_TEMPLATE])

        # Generate sections based on template
        sections = []
        for section_type in template['sections']:
            if section_type == 'EXECUTIVE_SUMMARY':
                content = self._generate_executive_summary(findings, campaign_id)
            elif section_type == 'FINDINGS':
                content = self._generate_findings_section(findings, template.get('include_technical_details', False))
            elif section_type == 'CREDENTIAL_MODE_COMPARISON' and credential_mode_comparison:
                content = self._generate_credential_comparison_section(credential_mode_comparison)
            elif section_type == 'ATTESTATIONS' and zk_attestations:
                content = self._generate_attestations_section(zk_attestations)
            else:
                content = f"[{section_type} content placeholder]"

            sections.append(self.create_section(
                section_type=section_type,
                title=section_type.replace('_', ' ').title(),
                content=content,
                classification_level=classification_level
            ))

        # Create default embargo policy if not provided
        if not embargo_policy:
            embargo_policy = DisclosureEmbargoPolicy(
                policy_id=f"embargo-{uuid4().hex[:12]}",
                embargo_type=EmbargoType.NONE
            )

        # Compute integrity
        section_hashes = [s.content_hash for s in sections]
        merkle_root = self._compute_merkle_root(section_hashes)

        dossier_content = {
            'dossier_id': dossier_id,
            'campaign_id': campaign_id,
            'tenant_id': tenant_id,
            'sections': [{'section_id': s.section_id, 'hash': s.content_hash} for s in sections]
        }
        dossier_hash = self._compute_hash(dossier_content)

        # Create verifier pack reference
        verifier_pack_ref = {
            'pack_id': f"vpack-{uuid4().hex[:12]}",
            'pack_hash': self._compute_hash({'version': self.VERIFIER_PACK_VERSION, 'dossier_id': dossier_id}),
            'verification_script_version': self.VERIFIER_PACK_VERSION,
            'download_url': f"https://verify.frostgate.io/packs/{dossier_id}"
        }

        manifest = DossierManifest(
            dossier_id=dossier_id,
            version="1.0.0",
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            created_at=now,
            dossier_type=dossier_type,
            template_type=template_type,
            classification_level=classification_level,
            sections=sections,
            findings_summary=self.create_finding_summary(findings),
            credential_mode_comparison=credential_mode_comparison,
            evidence_bundle_refs=evidence_bundle_refs,
            zk_attestation_refs=zk_attestations or [],
            disclosure_embargo_policy=embargo_policy,
            verifier_pack_ref=verifier_pack_ref,
            integrity={
                'dossier_hash': dossier_hash,
                'merkle_root': merkle_root,
                'anchor_refs': []
            },
            generation_metadata={
                'generator_version': '1.0.0',
                'generation_duration_ms': 0,
                'template_version': '1.0.0'
            }
        )

        self._dossiers[dossier_id] = manifest
        return manifest

    def _generate_executive_summary(self, findings: list[Finding], campaign_id: str) -> str:
        """Generate executive summary content."""
        critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)

        return f"""Executive Summary
Campaign ID: {campaign_id}
Total Findings: {len(findings)}
Critical: {critical}
High: {high}

This dossier presents the findings from the security assessment campaign.
"""

    def _generate_findings_section(self, findings: list[Finding], include_technical: bool) -> str:
        """Generate findings section content."""
        content = "Findings\n\n"
        for finding in sorted(findings, key=lambda f: f.severity.value, reverse=True):
            content += f"[{finding.severity.value}] {finding.title}\n"
            content += f"  Category: {finding.category}\n"
            content += f"  Description: {finding.description}\n"
            if include_technical and finding.cve_refs:
                content += f"  CVEs: {', '.join(finding.cve_refs)}\n"
            content += "\n"
        return content

    def _generate_credential_comparison_section(self, comparison: CredentialModeComparison) -> str:
        """Generate credential mode comparison section."""
        return f"""Credential Mode Comparison

Unauthenticated Testing:
  - Findings: {comparison.unauthenticated['findings_count']}
  - Coverage: {comparison.unauthenticated['coverage_percentage']}%
  - Cost: ${comparison.unauthenticated['cost_usd']}

Authenticated Testing:
  - Findings: {comparison.authenticated['findings_count']}
  - Coverage: {comparison.authenticated['coverage_percentage']}%
  - Cost: ${comparison.authenticated['cost_usd']}

Delta Analysis:
  - Additional findings with authentication: {comparison.delta_analysis['additional_findings_with_auth']}
  - Coverage improvement: {comparison.delta_analysis['coverage_improvement']}%
  - Cost difference: ${comparison.delta_analysis['cost_difference']}
"""

    def _generate_attestations_section(self, attestations: list[ZKAttestation]) -> str:
        """Generate ZK attestations section."""
        content = "Zero-Knowledge Attestations\n\n"
        for att in attestations:
            content += f"Attestation: {att.attestation_type}\n"
            content += f"  Proof System: {att.proof_system}\n"
            content += f"  Proof Hash: {att.proof_hash}\n\n"
        return content

    def apply_embargo(
        self,
        dossier_id: str,
        embargo_type: EmbargoType,
        embargo_until: Optional[datetime] = None,
        approvers: Optional[list[str]] = None,
    ) -> bool:
        """Apply or update embargo on a dossier."""
        if dossier_id not in self._dossiers:
            return False

        dossier = self._dossiers[dossier_id]
        dossier.disclosure_embargo_policy = DisclosureEmbargoPolicy(
            policy_id=f"embargo-{uuid4().hex[:12]}",
            embargo_type=embargo_type,
            embargo_until=embargo_until,
            disclosure_approvers=approvers or []
        )
        return True

    def check_disclosure_allowed(self, dossier_id: str) -> tuple[bool, str]:
        """Check if disclosure is currently allowed for a dossier."""
        if dossier_id not in self._dossiers:
            return False, "Dossier not found"

        dossier = self._dossiers[dossier_id]
        policy = dossier.disclosure_embargo_policy

        if policy.embargo_type == EmbargoType.NONE:
            return True, "No embargo"

        if policy.embargo_type == EmbargoType.TIME_BASED:
            if policy.embargo_until and datetime.now(timezone.utc) >= policy.embargo_until:
                return True, "Embargo period ended"
            return False, f"Embargo until {policy.embargo_until}"

        if policy.embargo_type == EmbargoType.APPROVAL_REQUIRED:
            return False, f"Requires approval from: {', '.join(policy.disclosure_approvers)}"

        if policy.embargo_type == EmbargoType.COORDINATED_DISCLOSURE:
            return False, "Coordinated disclosure in progress"

        return False, "Unknown embargo state"

    def export_dossier_manifest(self, dossier_id: str) -> Optional[dict]:
        """Export dossier manifest as dictionary."""
        if dossier_id not in self._dossiers:
            return None

        dossier = self._dossiers[dossier_id]
        return {
            'dossier_id': dossier.dossier_id,
            'version': dossier.version,
            'campaign_id': dossier.campaign_id,
            'tenant_id': dossier.tenant_id,
            'created_at': dossier.created_at.isoformat(),
            'dossier_type': dossier.dossier_type.value,
            'template_type': dossier.template_type.value,
            'classification_level': dossier.classification_level,
            'sections': [
                {
                    'section_id': s.section_id,
                    'title': s.title,
                    'section_type': s.section_type,
                    'content_hash': s.content_hash
                }
                for s in dossier.sections
            ],
            'findings_summary': dossier.findings_summary,
            'evidence_bundle_refs': dossier.evidence_bundle_refs,
            'zk_attestation_refs': [
                {
                    'attestation_id': a.attestation_id,
                    'attestation_type': a.attestation_type,
                    'proof_hash': a.proof_hash,
                    'proof_system': a.proof_system
                }
                for a in dossier.zk_attestation_refs
            ],
            'disclosure_embargo_policy_ref': {
                'policy_id': dossier.disclosure_embargo_policy.policy_id,
                'embargo_type': dossier.disclosure_embargo_policy.embargo_type.value
            },
            'verifier_pack_ref': dossier.verifier_pack_ref,
            'integrity': dossier.integrity
        }
