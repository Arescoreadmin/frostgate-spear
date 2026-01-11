# Frost Gate Spear Threat Model

**Version:** 1.0.0
**Blueprint Reference:** v6.1 §6
**Last Updated:** 2026-01-11

## Overview

This document defines the threat model for Frost Gate Spear per Blueprint v6.1 §6.
Each threat maps to mitigations, tests, monitoring signals, and runbooks.

---

## 1. Malicious Operator

### Description
An authorized operator attempts to:
- Execute unauthorized actions outside approved scope
- Bypass safety controls
- Exfiltrate sensitive data
- Cover tracks by manipulating evidence

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Execution Permit Token required | `execution.permit.v1` schema enforced | §2.1, §4.2.3 |
| Per-action Policy Envelope | OPA policy evaluation on every action | §2.2 |
| Dual attestation | Witness service co-signs decisions | §5.4 |
| SoD enforcement | Approver cannot start own campaigns | §5.2 |
| Step-up auth for LIVE modes | MFA/hardware token required | §5.2 |
| Immutable audit trail | Append-only ledger with witness signatures | §10 |
| CR reference required | Non-SIM requires change request | §2.9 |

### Tests
- `test_malicious_operator_scope_bypass` - Verify actions outside scope are denied
- `test_malicious_operator_self_approval` - Verify SoD prevents self-approval
- `test_malicious_operator_evidence_tampering` - Verify tampered evidence detected

### Monitoring Signals
- Alert: Repeated policy denials for same operator
- Alert: Step-up auth failures
- Alert: Attempts to modify historical events
- Metric: `fgs_policy_denial_total{reason="scope_violation"}`

### Runbook
1. Immediately revoke operator's active permits
2. Freeze associated campaigns
3. Export audit trail with witness attestations
4. Escalate to security team
5. Conduct forensic review

---

## 2. Compromised Orchestrator

### Description
The campaign orchestrator component is compromised and attempts to:
- Execute actions without valid permits
- Bypass policy evaluation
- Inject malicious actions into campaigns
- Modify or delete evidence

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Permit signature verification | Orchestrator must verify permit sig | §4.2.3 |
| Runtime behavior guard | Sidecar enforces behavior contract | §2.8, §8.1 |
| Dual attestation | Guard co-attests all decisions | §5.4 |
| Service identity (SPIFFE) | mTLS with SVID verification | §5.1 |
| Evidence agent isolation | Separate process for evidence | §3.2 |
| Network policies | No bypass paths enforced | §12 |

### Tests
- `test_compromised_orchestrator_no_permit` - Actions rejected without permit
- `test_compromised_orchestrator_invalid_sig` - Invalid signatures rejected
- `test_compromised_orchestrator_guard_enforcement` - Guard blocks violations

### Monitoring Signals
- Alert: Permit validation failures
- Alert: Guard/orchestrator decision mismatch
- Alert: Unexpected orchestrator network connections
- Metric: `fgs_permit_validation_failure_total`

### Runbook
1. Trigger scoped revocation for orchestrator (≤2s)
2. Quarantine affected node
3. Verify evidence chain integrity
4. Rotate service credentials
5. Deploy from known-good image

---

## 3. Compromised Tool Container

### Description
A tool container is compromised and attempts to:
- Execute unauthorized system calls
- Access data outside its scope
- Exfiltrate data via covert channels
- Persist beyond its execution window

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Tool sandbox | Seccomp, AppArmor, gVisor isolation | §12 |
| Tool certification | SIM/SHADOW/LIVE certification levels | §3.2 |
| Network policies | Egress controlled by entrypoint-controller | §7.2, §12 |
| Read-only filesystem | Immutable container filesystem | §12 |
| Resource limits | CPU/memory/network quotas | §12 |
| Execution time limits | Hard timeout enforcement | §8.1 |
| Signed tool images | Only signed images execute | §12 |

### Tests
- `test_tool_sandbox_syscall_filtering` - Blocked syscalls verified
- `test_tool_sandbox_network_isolation` - Network egress controlled
- `test_tool_container_persistence` - No persistence after execution

### Monitoring Signals
- Alert: Blocked syscall attempts
- Alert: Unauthorized network connections
- Alert: Resource limit breaches
- Metric: `fgs_sandbox_violation_total{type="syscall"}`

### Runbook
1. Terminate tool container immediately
2. Revoke tool certification
3. Quarantine all instances of tool version
4. Analyze container for malware
5. Update tool catalog blocklist

---

## 4. Tenant Attempting Deception

### Description
A tenant attempts to:
- Inject false scope to attack out-of-scope assets
- Manipulate findings to hide vulnerabilities
- Submit falsified authorization documents
- Access other tenants' data

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Canonical scope validation | Strict schema, no vague scope | §4.2.2 |
| Authorization signature verification | Signed auth refs for non-LAB | §4.2.2 |
| Tenant isolation | Cryptographic + access isolation | §2.10 |
| Per-tenant encryption keys | Tenant-specific KMS keys | §5.3 |
| Scope hash verification | Immutable scope_hash | §4.2.2 |
| Evidence integrity | Content-addressed bundles | §10 |

### Tests
- `test_tenant_scope_injection` - Invalid scope rejected
- `test_tenant_cross_access` - Cross-tenant access denied
- `test_tenant_auth_forgery` - Invalid signatures rejected

### Monitoring Signals
- Alert: Scope validation failures
- Alert: Cross-tenant access attempts
- Alert: Authorization signature failures
- Metric: `fgs_tenant_isolation_violation_total`

### Runbook
1. Suspend tenant campaigns
2. Audit recent tenant activities
3. Verify scope definitions
4. Contact tenant security team
5. Review authorization chain

---

## 5. Poisoned Evidence Pipeline

### Description
Attacker attempts to:
- Inject false evidence into bundles
- Modify evidence after collection
- Break evidence chain integrity
- Prevent anchoring to create gaps

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Content-addressed storage | SHA-256 hashes for all evidence | §10 |
| Evidence chain hashing | Each event links to previous | §4.2.4 |
| Daily anchoring | Required, missing anchors fail build | §2.4, §10 |
| Witness signatures | Independent witness attestation | §5.4, §10 |
| Immutable evidence store | Append-only with replication | §10 |
| Customer verifier kit | Independent verification | §0, §10 |

### Tests
- `test_evidence_tampering_detection` - Tampered evidence detected
- `test_evidence_chain_integrity` - Chain breaks detected
- `test_daily_anchor_enforcement` - Missing anchors fail CI

### Monitoring Signals
- Alert: Evidence hash mismatch
- Alert: Chain integrity failure
- Alert: Missed daily anchor
- Metric: `fgs_evidence_integrity_failure_total`

### Runbook
1. Halt evidence ingestion
2. Identify contamination scope
3. Restore from last known-good anchor
4. Re-verify evidence chain
5. Notify affected tenants

---

## 6. Key Compromise

### Description
Cryptographic keys are compromised:
- Service signing keys
- Witness keys
- Tenant encryption keys
- Environment signing keys

### Mitigations

| Mitigation | Implementation | Blueprint Reference |
|------------|---------------|---------------------|
| Key hierarchy | Offline root, env, service, witness | §5.3 |
| Short-lived service keys | Automatic rotation | §5.3 |
| Separate witness trust domain | Isolated witness keys | §5.3 |
| Hardware security modules | HSM for critical keys | §5.3 |
| Key access audit logging | All key operations logged | §5.3 |
| Revocation propagation | ≤2s revocation effect | §2.5 |
| CRL service | Certificate revocation list | §3.3 |

### Tests
- `test_key_rotation` - Keys rotate on schedule
- `test_revocation_propagation` - Revocation within SLA
- `test_compromised_key_detection` - Anomalous usage detected

### Monitoring Signals
- Alert: Key access anomaly
- Alert: Failed signature verifications
- Alert: Revocation propagation delay
- Metric: `fgs_key_operation_total{operation="sign"}`

### Runbook
1. Immediately revoke compromised key via CRL
2. Verify revocation propagated (≤2s)
3. Generate new key in HSM
4. Re-sign affected artifacts
5. Notify affected parties
6. Conduct compromise analysis

---

## Threat Matrix Summary

| Threat | Likelihood | Impact | Risk | Primary Mitigations |
|--------|-----------|--------|------|---------------------|
| Malicious Operator | Medium | High | High | SoD, Dual Attestation, Permits |
| Compromised Orchestrator | Low | Critical | High | Guard, Signatures, Network Policy |
| Compromised Tool | Medium | Medium | Medium | Sandbox, Certification, Isolation |
| Tenant Deception | Medium | Medium | Medium | Scope Validation, Tenant Isolation |
| Poisoned Evidence | Low | High | Medium | Content-Addressing, Anchoring, Witness |
| Key Compromise | Low | Critical | High | HSM, Rotation, Hierarchy, CRL |

---

## Security Controls Mapping

### Blueprint Non-Negotiables Coverage

| Non-Negotiable | Threats Addressed | Implementation Status |
|----------------|-------------------|----------------------|
| No bypass path (#1) | All | Execution Permit Token enforced |
| Per-action Policy Envelope (#2) | Malicious Operator | OPA policy on every action |
| Deterministic replay (#3) | Evidence Poisoning | Replay service with determinism protocol |
| Evidence-first (#4) | Evidence Poisoning | Content-addressed bundles, daily anchoring |
| Scoped revocation (#5) | Key Compromise | ≤2s revocation via CRL service |
| SIM-first (#6) | Compromised Tool | 1000 SIM runs before LIVE_GUARDED |
| Budget enforcement (#7) | Resource Abuse | 90% soft, 100% hard limits |
| Runtime behavior integrity (#8) | Compromised Orchestrator | Sidecar guard enforcement |
| Machine-enforced change control (#9) | Malicious Operator | CR refs required for non-SIM |
| Tenant isolation (#10) | Tenant Deception | Cryptographic + access isolation |
| Redaction enforced (#11) | Data Exfiltration | Fail-closed redaction |
| Customer verifiability (#12) | Evidence Poisoning | Verifier kit for independent validation |

---

## Review Schedule

- **Quarterly:** Full threat model review
- **On Change:** Update when architecture changes
- **Post-Incident:** Review and update after security incidents

## References

- Blueprint v6.1 §6 (Threat Model and Insider Resistance)
- Blueprint v6.1 §5 (Identity, Authorization, Key Management)
- Blueprint v6.1 §10 (Evidence + Verifiability)
- Blueprint v6.1 §12 (Platform Security)
