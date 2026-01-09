Frost Gate Spear — On-Rails Project Charter (DoD/Gov-Class Revision)

Date: 2025-10-15

Purpose: keep the Frost Gate Spear program within scope, compliant with civilian + defense frameworks, edged but controllable, and survivable under hostile audit. This document is the single attachment you pull out whenever someone asks you to “just make it more aggressive.”

1) Non-Negotiables (Scope Locks)

These are welded, not negotiable.

Policy Envelopes required for every executable action and campaign.

Fields: mode, risk_tier, mission_type, classification_level, scope_id, approvals[], budget_cap, valid_from/to.

Rules of Engagement (ROE) Engine Mandatory

ROE declared per mission.

Enforced automatically by Policy Interpreter.

Blocks disallowed TTPs, disallowed times, disallowed assets, alert-footprint caps.

Multi-Level Security (MLS) Required

Execution isolated by classification ring: UNCLASS, CUI, SECRET, TOPSECRET.

No cross-ring raw data or raw gradients.

Every artifact labeled with classification level.

SIM-First Validation (per ring)

1,000 SIM runs, zero violations, before any promotion to Lab/Canary/Prod for that classification level.

Blast Radius & Impact Caps

Each mission has a bound on operational impact.

Enforced via Target Impact Estimator (TIE).

Budget Enforcement

Throttle at soft limit; refusal at hard limit.

Daily caps per tenant and per classification ring.

Forensic Completeness ≥ 0.95

Required for all promotions, audits, mission sign-offs, and model upgrades.

All logs are WORM + externally timestamp-anchored.

No Autonomous Scope Expansion

No lateral movement unless explicitly approved in the ROE + Policy Envelope.

No live exploitation without AO approval

Risk-tier 3 or classification >CUI requires mission approval from Authorizing Official.

Zero-Trust Internal RPC

mTLS + per-service identity + OPA checks on every call.

SBOM + Artifact Provenance

Every binary, container, scenario, and model must have:

SBOM

Build provenance

Signature

Attestation hash

Adversary Personas Allowed Only via Signed Packs

China/Russia/Iran/APT/Insider personas must be installed as signed modules.

Personas modify planner biases but cannot override ROE or safety constraints.

2) Governance Gates (Machine-Checkable)
Security Gate

Red-team review + gov security review passed.

Tool catalog risk tiers validated.

No persona violating ROE constraints.

MLS isolation validated across enclaves.

Safety Gate

1,000 SIM runs per ring.

0 policy violations.

Deception/honeypot false-positive rate below threshold.

Concurrency limits observed in multi-attack tests.

Forensic Gate

Forensic completeness ≥ 0.95.

Replay success ≥ 0.95.

Tamper-evident Merkle lineage for:

plan hashes

scenario hashes

model versions

policy bundle IDs

Impact Gate (NEW)

TIE (Target Impact Estimator) scoring must remain within envelope-defined blast radius.

Mission-critical systems require “zero-impact mode” unless AO signs escalated ROE.

Performance Gate

Costs < budget cap.

Latency SLOs green.

Alert footprint within mission ROE.

Ops & Mission Gate

Mission operator or SOC must successfully replay results.

Attack persona behavior recorded + explained via Blue Box explainer.

For classified missions: AO sign-off required.

FL Ring Gate (NEW)

No cross-ring gradient contamination.

DP bounds intact.

FL lineage validated.

Promotion path per ring:
SIM → Lab → Canary → Mission / Production

3) RACI

Unchanged roles + added responsibilities:

Product / Mission Owner

Own mission profiles, ROEs, classification boundaries.

Security / Red Team / Gov Security Liaison

Approve adversary personas.

Validate TIE scoring logic.

SRE / Platform / Enclave Ops

Maintain enclave integrity.

Own SBOM + supply chain pipelines.

Data / ML / FL

Own ring-restricted FL.

Ensure no gradient leakage.

Manage persona models.

Legal / Privacy / Gov Compliance

Validate ROE legality.

Validate mission signature requirements.

Own classification-based data handling.

Gov Program Office / Customer Success

Ensure mission ROE + boundary compliance.

Manage AO approvals.

Audit / IG / Risk

Validate explainability + replay.

Inspect lineage, SBOM, and provenance.

4) Change Control (Gov-Strict)

CR must include:

Missions affected

Classification rings impacted

ROE changes

Blast radius changes

SBOM deltas

Model lineage deltas

Scenario hashes & impact simulations

Gov deployments require AO approval for any change to:

ROE

Risk tier

Classification level

Adversary persona

Scenario families in risk-tier 3

No work before approvals. No execution before signatures anchored.

5) Acceptance Criteria (DoD-tier)
V1 – Enterprise Core

(same as previous, baseline)

V2 – Autonomous Multi-Attack (Upgraded)

Multi-entry, multi-branch DAGs live

Constrained concurrency validated

Adversary personas integrated (UNCLASS only)

Counterfactual analysis integrated into battle assessor

V3 – Government-Ready

MLS enclaves operational (UNCLASS/CUI)

ROE Engine fully enforced

TIE (Target Impact Estimator) in production

Blue Box explainability live

SBOM + provenance pipeline complete

Zero-trust enforced on all internal RPC

V4 – Mission-Grade

Live Purple-Team Mode (attacker + defender training)

Persona-specific kill chain preferences stable

FL rings functional (UNCLASS + CUI)

Blast radius enforcement verified

Defender reaction modeling complete

V5 – DoD/IC-Class

SECRET/TOPSECRET enclaves validated

Air-gapped model couriering pipeline available

Deception-aware planner tuned

Cross-ring policy constraints validated

Compliance mapping complete (FIPS, STIG, NIST 800-53, ICD 503, FedRAMP High)

6) KPIs (Upgraded)

Time-to-objective ↓ (per mission + per ring)

Forensic completeness ≥ 95%

Replay success ≥ 95%

Impact prediction accuracy ≥ 90%

Persona fidelity score ≥ threshold

FL uplift per ring ≥ threshold

MLS isolation failures = 0

ROE violations = 0

SBOM coverage = 100%

Cross-ring gradient leakage = 0

7) Red Lines (Strengthened)

No action outside mission ROE.

No modification to classification level by any automated system.

No persona override of ROE, safety, or policy envelope.

No cross-ring contamination.

No destructive operations without AO signature.

No scenario execution without scenario hash match.

No un-signed or un-attested binaries.

8) Sign-Off Template (Extended)

“I, <name>, approve <change/model/capability/mission> for <environment & classification_ring> under <mission_type>, with scope hash <sha256> and plan hash <sha256>. I attest full compliance with ROE, classification constraints, and authorized impact bounds.”

Signature (AO or delegated authority): <base64>
Date: <ISO>
Role: <Product | Security | AO | Gov Compliance | etc.>

9) References

docs/Blueprint_Frost Gate Spear_v6_gov_dod.md

policy/roe_policy.rego (new)

mls_rings/*.yaml

adversary_personas/*.json

sbom/provenance/*

.github/workflows/secure_build.yml

fl_rings/*