# Frost Gate Spear Blueprint v6.1 - Showstopper Edition

> **Status**: AUTHORITATIVE - This document supersedes v6 and all prior versions.
> **Date**: 2025-12-01
> **Classification**: UNCLASS // FOUO

## Executive Summary

Blueprint v6.1 "Showstopper Edition" introduces mandatory enforcement requirements that MUST be implemented before any production deployment. This version addresses critical gaps identified in v6 audit findings including:

- Permit enforcement with cryptographic verification
- Persistent nonce storage for replay protection
- Runtime behavior guard with mode-aware contracts
- ABAC/SoD/Step-up authentication enforcement
- Canonical scope linting with runtime drift detection
- Gate F no-bypass verification
- Target safety envelope runtime enforcement

**Non-compliance with v6.1 requirements is a deployment blocker.**

## 1. Permit Enforcement Requirements

### 1.1 Execution Permit Validation

Permit validation MUST occur at three checkpoints:

1. **Mission Preflight/Start** - Before any execution begins
2. **Per-Action Execution** - BEFORE EVERY action is executed
3. **TTL Expiry Check** - Continuous monitoring with safe halt on expiry

### 1.2 Signature Verification

- Permits MUST be cryptographically signed using Ed25519
- Signature verification MUST use a trust store with known public keys
- "Signature verification" MUST NOT be implemented as field presence checks
- Failed signature verification MUST halt execution immediately

### 1.3 Nonce Replay Protection

- Nonces MUST be stored persistently (SQLite or equivalent)
- In-memory nonce tracking is NOT acceptable
- Nonce store MUST survive restarts and support multi-instance deployment
- Reused nonces MUST be rejected with clear error codes

### 1.4 Permit Binding

Each action execution MUST validate:
- Tool is in permit allowlist
- Target is in permit allowlist
- Entrypoint is in permit allowlist
- Permit TTL has not expired

## 2. Runtime Behavior Guard

### 2.1 Mode-Aware Behavior Contracts

Each execution mode has a behavior contract defining:

| Mode | Max Autonomy | Destructive Confirmation | Scope Expansion | Live Targets | Rate Limit |
|------|--------------|-------------------------|-----------------|--------------|------------|
| SIM | FULL | No | No | No | 1000/min |
| LAB | HIGH | Yes | No | Yes | 60/min |
| CANARY | MEDIUM | Yes | No | Yes | 30/min |
| SHADOW | LOW | Yes | No | Yes | 10/min |
| LIVE_GUARDED | LOW | Yes | No | Yes | 5/min |
| LIVE_AUTONOMOUS | HIGH | Yes | No | Yes | 10/min |

### 2.2 Rate Limiting

- Rate limits MUST use real counters, not field presence
- Rate counters MUST be persistent across restarts
- Exceeding rate limits MUST block action execution

### 2.3 Human Confirmation Boundaries

- Destructive operations in non-SIM modes REQUIRE human confirmation
- Confirmation MUST be cryptographically attestable
- Missing confirmation MUST return REQUIRE_CONFIRMATION decision

### 2.4 Dual Attestation

For modes requiring dual attestation (CANARY, SHADOW, LIVE_*):
- Control plane MUST provide attestation
- Runtime guard MUST provide independent attestation
- Combined hash MUST be recorded
- Witness checkpoints SHOULD be requested when available

## 3. ABAC/SoD/Step-up Enforcement

### 3.1 Attribute-Based Access Control

Access decisions MUST consider:
- Subject attributes (clearance, roles, session validity)
- Resource attributes (classification, scope)
- Environmental attributes (time window, network zone)
- Action attributes (type, risk level)

### 3.2 Separation of Duties

The following MUST be enforced:
- Executor MUST NOT be an approver for risk tier 2+ in LIVE modes
- Incompatible role pairs MUST NOT be active simultaneously
- SoD violations MUST block execution with ABAC.SOD.VIOLATION

### 3.3 Step-up Authentication

Step-up MUST be required for:
- Destructive operations
- Scope expansion requests
- Credential access
- Classification changes
- Risk tier 3 in non-SIM modes
- Classified operations (SECRET, TOPSECRET)

Accepted step-up methods:
- Hardware token
- Biometric verification
- Dual approval

Step-up validity: 5 minutes from authentication

## 4. Canonical Scope Enforcement

### 4.1 Scope Validation

Scopes MUST be validated for:
- Valid UUID format for scope_id
- Strongly-typed asset IDs (no free text)
- Valid network CIDRs
- Valid domain formats
- Time window within 72-hour maximum
- Authorization reference for PROD/MISSION environments
- Contact information for non-SIM environments

### 4.2 Asset ID Patterns

Asset IDs MUST match patterns:
- HOST: `HOST-[A-Z0-9]{9,}`
- IP: `IP-x.x.x.x`
- CIDR: `CIDR-x.x.x.x/n`
- DOMAIN: `DOMAIN-domain.tld`
- SERVICE: `SVC-IDENTIFIER`
- CONTAINER: `CTR-[a-f0-9]{12,}`
- CLOUD: `(AWS|GCP|AZURE)-RESOURCE_ID`

### 4.3 Runtime Drift Detection

Drift MUST be detected by comparing executed actions against approved scope.

Drift Severity Levels:
- P1 (<=5%): Alert only
- P2 (5-10%): HALT_AND_REVOKE
- P3 (10-20%): HALT_AND_REVOKE
- P4 (20-40%): HALT_AND_REVOKE
- P5 (>40%): HALT_AND_REVOKE

P2+ drift MUST halt execution and revoke permit.

## 5. Target Safety Envelope

### 5.1 Health Probe Gating

Before targeting any asset:
- Health probe MUST confirm target is reachable
- Health probe MUST confirm target matches expected fingerprint
- Failed health probes MUST block action

### 5.2 Stop Conditions

Execution MUST stop when:
- Target enters degraded state
- Impact score exceeds blast radius cap
- Forensic completeness drops below 95%
- Rate limit exceeded
- Budget exhausted

### 5.3 Impact Prediction

TIE (Target Impact Estimator) MUST:
- Predict impact before each action
- Reject actions exceeding blast radius
- Track cumulative impact

## 6. Gate F - No-Bypass Verification

### 6.1 CI Static Check

CI MUST verify:
- Tools cannot be invoked directly (only via orchestrator)
- No public tool endpoints exist
- Direct invocation is disabled in configuration
- All execution paths go through permit validation

### 6.2 CI Runtime Test

CI MUST include a test that:
- Attempts direct tool invocation
- Verifies invocation is REJECTED
- Verifies rejection is LOGGED
- Fails the build if direct invocation succeeds

### 6.3 Admission Controller Requirements

The following admission controllers MUST be enabled:
- tool_invocation_validator
- orchestrator_origin_validator
- permit_validator

## 7. Evidence Gate (Gate D)

### 7.1 Evidence Requirements

Before promotion:
- Evidence bundles MUST be assembled
- Bundle hashes MUST be computed
- Daily anchors MUST be signed
- Redaction report MUST confirm secrets removed
- Forensic completeness MUST be >= 95%

### 7.2 Bundle Signing

Evidence bundles MUST be signed with:
- Ed25519 or ECDSA signatures
- Key from trusted key registry
- Timestamp from RFC 3161 server (for PROD)

## 8. CLI Requirements

### 8.1 `fgs watch` Command

The CLI MUST support:
```
fgs watch <campaign_id> --verify --resume-from <hash> --json
```

Features:
- Verify ledger hash chain integrity
- Verify entry signatures
- Verify witness checkpoints (if present)
- Detect gaps in sequence numbers
- Detect tampering in hash chain
- Resume verification from a specific hash
- Output in JSON format for automation

### 8.2 Output Format

```json
{
  "campaign_id": "uuid",
  "verification_status": "VALID|INVALID|INCOMPLETE",
  "entries_verified": 1000,
  "chain_integrity": true,
  "gaps_detected": [],
  "tampering_detected": [],
  "witness_checkpoints_verified": 5,
  "resume_hash": "sha256:abc..."
}
```

## 9. OPA Bundle Signing

### 9.1 Requirements

- OPA policy bundles MUST be signed
- Signatures MUST be verified before loading
- Unsigned bundles MUST be rejected
- Verification failure MUST block deployment

### 9.2 Implementation Status

> **TODO**: OPA bundle signing validation is a BLOCKING requirement.
> This check MUST fail CI until implementation is complete.

## 10. Schema Backward Compatibility

### 10.1 Gate A Enhancement

Schema validation MUST include:
- Field presence validation (existing)
- Backward compatibility checks (NEW)
- No breaking changes to required fields
- Additive-only changes for minor versions

## Appendix A: Failure Codes

| Code | Description | Action |
|------|-------------|--------|
| PERMIT.EXPIRED | Permit TTL exceeded | Halt execution |
| PERMIT.SIGNATURE.INVALID | Signature verification failed | Reject permit |
| PERMIT.NONCE.REUSED | Replay attack detected | Reject permit |
| ABAC.SOD.VIOLATION | Separation of duties violation | Block action |
| ABAC.STEPUP.REQUIRED | Step-up authentication needed | Request auth |
| RUNTIME.SCOPE.DRIFT | Significant scope drift | HALT_AND_REVOKE |
| RUNTIME.RATE.EXCEEDED | Rate limit exceeded | Block action |
| STRUCTURAL.NO_BYPASS.* | Direct tool invocation detected | Reject and log |

## Appendix B: Implementation Checklist

- [ ] Permit module with Ed25519 verification
- [ ] Persistent nonce store (SQLite)
- [ ] Per-action permit validation
- [ ] Runtime behavior guard with mode contracts
- [ ] Rate limiting with persistent counters
- [ ] ABAC policy evaluation in preflight
- [ ] SoD enforcement
- [ ] Step-up authentication flow
- [ ] Canonical scope linting (policy + runtime)
- [ ] Scope drift detector
- [ ] Target safety envelope checks
- [ ] Gate F no-bypass in CI
- [ ] Gate A backward compatibility
- [ ] Gate D evidence stub
- [ ] OPA bundle signing stub
- [ ] CLI `fgs watch` command

## Appendix C: Version History

| Version | Date | Changes |
|---------|------|---------|
| v6.1 | 2025-12-01 | Showstopper Edition - mandatory enforcement |
| v6 | 2025-10-15 | DoD/Gov class, MLS, TIE, personas |
| v5 | 2025-08-01 | FL integration, forensics |
