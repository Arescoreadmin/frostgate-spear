# Frost Gate Spear Blueprint v6 - DoD/Government Class

> **SUPERSEDED**: This document has been superseded by Blueprint v6.1 Showstopper Edition.
> See [Blueprint_Frost_Gate_Spear_v6.1_Showstopper.md](Blueprint_Frost_Gate_Spear_v6.1_Showstopper.md) for current requirements.
> v6 remains available for historical reference only.

## Executive Summary

Frost Gate Spear is an autonomous red team simulation and adversary emulation platform designed for defense and government environments. This blueprint defines the technical architecture, safety controls, and operational constraints required for deployment across classification levels from UNCLASS through TOP SECRET.

## 1. Architecture Overview

### 1.1 Core Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FROST GATE SPEAR PLATFORM                        │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   Policy    │  │    ROE      │  │   Safety    │  │    MLS     │ │
│  │ Interpreter │  │   Engine    │  │ Constraints │  │  Manager   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   Planner   │  │  Executor   │  │     TIE     │  │  Blue Box  │ │
│  │  (Attack)   │  │   (Sim)     │  │  (Impact)   │  │ (Explain)  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Forensics  │  │     FL      │  │ Governance  │  │  Personas  │ │
│  │  Manager    │  │ Controller  │  │  Manager    │  │  Manager   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Subsystem Descriptions

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| **Policy Interpreter** | Validate and interpret policy envelopes | Schema validation, approval verification, constraint extraction |
| **ROE Engine** | Enforce Rules of Engagement | Scope validation, tool permissions, time windows, blast radius |
| **Safety Constraints** | Enforce safety boundaries | Red lines, simulation validation, no autonomous scope expansion |
| **MLS Manager** | Multi-Level Security | Ring isolation, Bell-LaPadula, gradient isolation |
| **Planner** | Generate attack plans | Kill chain mapping, persona alignment, DAG planning |
| **Executor** | Execute plans | Simulation, lab, canary, production modes |
| **TIE** | Target Impact Estimator | Impact prediction, blast radius monitoring |
| **Blue Box** | Explainability | Human-readable explanations, counterfactual analysis |
| **Forensics** | Audit trail | WORM logging, Merkle trees, replay capability |
| **FL Controller** | Federated Learning | Ring-isolated training, differential privacy |
| **Governance** | Approval workflows | Gate validation, budget enforcement |
| **Personas** | Adversary emulation | Signed persona packs, TTP preferences |

## 2. Classification Rings

### 2.1 Ring Hierarchy

```
TOPSECRET (Level 3) ──┐
                      │  Bell-LaPadula
SECRET    (Level 2) ──┤  No Read Up
                      │  No Write Down
CUI       (Level 1) ──┤
                      │
UNCLASS   (Level 0) ──┘
```

### 2.2 Ring Characteristics

| Ring | Network | FL Epsilon | AO Required | Key Frameworks |
|------|---------|------------|-------------|----------------|
| UNCLASS | Internet access | 1.0 | No | NIST-CSF, CIS |
| CUI | Proxy required | 0.5 | Risk 3+ | NIST 800-171, CMMC |
| SECRET | Air-gapped + CDS | 0.1 | Yes | ICD-503, JSIG |
| TOPSECRET | Physical isolation | 0.01 | Yes | ICD-705, DCID 6/3 |

## 3. Policy Enforcement

### 3.1 Policy Envelope

Every mission requires a policy envelope containing:

```yaml
envelope_id: uuid
mode: simulation | lab | canary | production | mission
risk_tier: 1 | 2 | 3
mission_type: red_team | purple_team | adversary_emulation | ...
classification_level: UNCLASS | CUI | SECRET | TOPSECRET
scope_id: reference to scope definition
approvals: list of signed approvals
budget_cap: resource limits
valid_from: ISO datetime
valid_to: ISO datetime
roe: rules of engagement
```

### 3.2 ROE Constraints

```yaml
roe:
  allowed_assets: [list of in-scope assets]
  disallowed_assets: [explicitly excluded]
  allowed_networks: [CIDR ranges]
  allowed_tools: [permitted tools]
  disallowed_tools: [prohibited tools]
  blast_radius_cap: 0-100 impact score
  alert_footprint_cap: max alerts
  lateral_movement_authorized: boolean
  destructive_ops_authorized: boolean
```

## 4. Governance Gates

### 4.1 Gate Definitions

| Gate | Criteria |
|------|----------|
| **Security** | Red team review, gov security review, tool catalog validated, MLS isolation |
| **Safety** | 1000 SIM runs, 0 policy violations, deception FP rate < 5% |
| **Forensic** | Completeness ≥ 95%, replay success ≥ 95%, Merkle lineage valid |
| **Impact** | TIE scoring within envelope, zero-impact mode for critical systems |
| **Performance** | Costs < budget, latency SLOs green, alert footprint within ROE |
| **Ops** | SOC replay successful, Blue Box explanation, AO sign-off (classified) |
| **FL Ring** | No cross-ring gradient contamination, DP bounds intact |

### 4.2 Promotion Path

```
SIM ──► LAB ──► CANARY ──► PRODUCTION/MISSION
  │       │        │              │
  └───────┴────────┴──────────────┘
         All gates must pass
         Per classification ring
```

## 5. Safety Architecture

### 5.1 Non-Negotiables

1. **Policy Envelopes** - Required for every executable action
2. **ROE Engine** - Mandatory, auto-enforced
3. **MLS Isolation** - No cross-ring raw data/gradients
4. **SIM-First** - 1000 runs, zero violations before promotion
5. **Blast Radius Caps** - TIE enforced
6. **Budget Enforcement** - Throttle at soft, refuse at hard
7. **Forensic Completeness** - ≥ 95% for all promotions
8. **No Autonomous Scope Expansion** - Explicit ROE approval required
9. **AO Approval** - Required for risk tier 3 and classification > CUI
10. **Zero-Trust RPC** - mTLS + per-service identity + OPA
11. **SBOM + Provenance** - Every artifact signed and attested
12. **Signed Persona Packs** - Cannot override ROE or safety

### 5.2 Red Lines

These are absolute prohibitions:

- No action outside mission ROE
- No automated classification level modification
- No persona override of ROE, safety, or policy
- No cross-ring contamination
- No destructive operations without AO signature
- No scenario execution without hash match
- No unsigned/un-attested binaries

## 6. Federated Learning

### 6.1 Ring Isolation

Each classification ring has isolated FL:
- Separate FL servers
- No raw gradient sharing across rings
- Differential privacy required for any cross-ring model sharing
- Secure aggregation for CUI and above

### 6.2 DP Configuration

| Ring | Epsilon | Delta | Min Participants |
|------|---------|-------|------------------|
| UNCLASS | 1.0 | 1e-5 | 3 |
| CUI | 0.5 | 1e-6 | 5 |
| SECRET | 0.1 | 1e-8 | 10 |
| TOPSECRET | 0.01 | 1e-10 | 20 |

## 7. Adversary Personas

### 7.1 Persona Categories

| Category | Min Ring | Use Case |
|----------|----------|----------|
| Script Kiddie | UNCLASS | Basic threat modeling |
| Cybercriminal | UNCLASS | Ransomware, financially motivated |
| Hacktivist | UNCLASS | Ideologically motivated |
| Nation State Lite | CUI | Limited APT capabilities |
| Nation State | SECRET | Full APT capabilities |
| APT Full | SECRET | Specific threat actor emulation |
| Insider | SECRET | Privileged insider threat |

### 7.2 Persona Constraints

```json
{
  "constraints": {
    "can_override_roe": false,
    "can_override_safety": false,
    "can_override_policy": false,
    "respects_blast_radius": true,
    "respects_scope": true
  }
}
```

Personas modify planner biases but CANNOT override any safety constraints.

## 8. Forensics and Audit

### 8.1 Logging Requirements

- WORM (Write Once Read Many) storage
- External timestamp anchoring
- Classification-level labeling
- Merkle tree for integrity verification
- Retention per ring requirements

### 8.2 Forensic Record Chain

```
Record N ──► Hash(Data + Previous_Hash) ──► Record N+1
                      │
                      └──► Merkle Root at mission end
```

### 8.3 Replay Capability

All missions must support forensic replay with ≥ 95% success rate.

## 9. SBOM and Provenance

### 9.1 Required Artifacts

Every binary, container, scenario, and model requires:

- SBOM (SPDX or CycloneDX format)
- Build provenance (SLSA Level 3)
- Cryptographic signature
- Attestation hash

### 9.2 Supply Chain Security

```yaml
secure_build:
  - Source code scanning (Semgrep, Gitleaks)
  - Vulnerability scanning (Trivy)
  - SBOM generation (Syft)
  - Provenance attestation (SLSA)
  - Container signing (Cosign)
```

## 10. Compliance Mapping

### 10.1 Framework Coverage

| Framework | Applicable Rings |
|-----------|-----------------|
| NIST CSF | All |
| CIS Controls | All |
| NIST 800-53 | CUI+ |
| NIST 800-171 | CUI |
| FedRAMP High | CUI+ |
| ICD-503 | SECRET+ |
| CNSSI-1253 | SECRET+ |
| FIPS 140-3 | CUI+ (crypto) |
| STIG | All |

## 11. Operational Procedures

### 11.1 Mission Lifecycle

1. **Create** - Define policy envelope and scenario
2. **Validate** - Policy interpreter validates envelope
3. **Approve** - Required approvals obtained
4. **Plan** - Planner generates execution plan
5. **Simulate** - 1000 SIM runs validate safety
6. **Execute** - Executor runs plan
7. **Monitor** - TIE tracks impact, Blue Box explains
8. **Complete** - Forensics finalized, gates validated

### 11.2 Sign-Off Template

```
I, <name>, approve <change/model/capability/mission> for
<environment & classification_ring> under <mission_type>,
with scope hash <sha256> and plan hash <sha256>.
I attest full compliance with ROE, classification constraints,
and authorized impact bounds.

Signature (AO or delegated authority): <base64>
Date: <ISO>
Role: <Product | Security | AO | Gov Compliance | etc.>
```

## 12. KPIs and Metrics

| Metric | Target | Red Line |
|--------|--------|----------|
| Time-to-objective | ↓ | N/A |
| Forensic completeness | ≥ 95% | < 90% |
| Replay success | ≥ 95% | < 90% |
| Impact prediction accuracy | ≥ 90% | < 80% |
| MLS isolation failures | 0 | > 0 |
| ROE violations | 0 | > 0 |
| SBOM coverage | 100% | < 100% |
| Cross-ring gradient leakage | 0 | > 0 |

## Appendix A: File References

- `policy/roe_policy.rego` - ROE enforcement policy
- `policy/safety_constraints.rego` - Safety constraint policy
- `policy/mls_policy.rego` - MLS enforcement policy
- `policy/policy_envelope.schema.json` - Envelope JSON schema
- `mls_rings/*.yaml` - Ring configurations
- `adversary_personas/*.json` - Persona definitions
- `fl_rings/*.yaml` - FL configurations
- `sbom/provenance/*` - SBOM schemas
- `.github/workflows/secure_build.yml` - CI/CD pipeline

## Appendix B: Version History

| Version | Date | Changes |
|---------|------|---------|
| v6 | 2025-10-15 | DoD/Gov class revision, MLS, TIE, personas |
| v5 | 2025-08-01 | FL integration, forensics |
| v4 | 2025-05-01 | Multi-attack DAGs |
| v3 | 2025-02-01 | ROE engine |
| v2 | 2024-11-01 | Policy envelopes |
| v1 | 2024-08-01 | Initial release |
