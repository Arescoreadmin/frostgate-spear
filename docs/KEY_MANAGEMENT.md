# Key Management Policy

**Version:** 1.0.0
**Blueprint Reference:** v6.1 §5.3
**Last Updated:** 2026-01-11

## Overview

This document defines the key management hierarchy, rotation policies, compromise runbooks,
and revocation propagation mechanisms per Blueprint v6.1 §5.3.

---

## 1. Key Hierarchy

Per Blueprint v6.1 §5.3, the following key hierarchy is implemented:

```
                    ┌─────────────────┐
                    │   Offline Root  │
                    │   (Organization)│
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
    │ Environment │   │   Witness   │   │   Tenant    │
    │Signing Keys │   │    Keys     │   │ Encryption  │
    │  (Rotated)  │   │ (Separate   │   │    Keys     │
    └──────┬──────┘   │Trust Domain)│   │ (Per-Tenant │
           │          └─────────────┘   │    KMS)     │
    ┌──────▼──────┐                     └─────────────┘
    │   Service   │
    │Signing Keys │
    │(Short-lived)│
    └─────────────┘
```

### 1.1 Offline Root Key

| Attribute | Value |
|-----------|-------|
| Purpose | Sign environment keys, establish trust root |
| Algorithm | RSA-4096 or ECDSA P-384 |
| Storage | Hardware Security Module (HSM), air-gapped |
| Access | Requires M-of-N quorum (e.g., 3-of-5) |
| Rotation | Annual or on compromise |
| Backup | Encrypted shards in geographically distributed vaults |

### 1.2 Environment Signing Keys

| Attribute | Value |
|-----------|-------|
| Purpose | Sign service keys, policy bundles, artifacts |
| Algorithm | ECDSA P-256 or EdDSA |
| Storage | HSM-backed, online |
| Rotation | Quarterly |
| Environments | Production, Staging, Development |

### 1.3 Service Signing Keys

| Attribute | Value |
|-----------|-------|
| Purpose | Sign API responses, events, permits |
| Algorithm | ECDSA P-256 |
| Storage | In-memory, derived from HSM |
| Rotation | Every 24 hours (automatic) |
| TTL | Maximum 48 hours |

### 1.4 Witness Keys (Separate Trust Domain)

| Attribute | Value |
|-----------|-------|
| Purpose | Independent checkpoint attestation |
| Algorithm | ECDSA P-256 or P-384 |
| Storage | Separate HSM from control plane |
| Rotation | Weekly |
| Trust Boundary | Isolated from control plane |

### 1.5 Tenant Encryption Keys

| Attribute | Value |
|-----------|-------|
| Purpose | Encrypt tenant-specific data at rest |
| Algorithm | AES-256-GCM |
| Storage | Tenant-specific KMS (AWS KMS, Azure Key Vault, etc.) |
| Rotation | Per tenant policy (default: 90 days) |
| Isolation | Cryptographically isolated per tenant |

---

## 2. Key Policies

### 2.1 Rotation Schedule

| Key Type | Rotation Period | Automatic | Notes |
|----------|----------------|-----------|-------|
| Offline Root | Annual | No | Manual ceremony required |
| Environment | Quarterly | Semi | Initiated manually, executed automatically |
| Service | 24 hours | Yes | Fully automated |
| Witness | Weekly | Yes | Automated with verification |
| Tenant Encryption | 90 days | Yes | Per-tenant configuration |

### 2.2 Key Generation Requirements

```yaml
key_generation:
  entropy_source: /dev/random or HSM TRNG
  minimum_entropy_bits: 256

  algorithms:
    asymmetric:
      - RSA-4096 (root only)
      - ECDSA-P256 (general use)
      - ECDSA-P384 (high security)
      - EdDSA (performance critical)
    symmetric:
      - AES-256-GCM
      - ChaCha20-Poly1305

  prohibited:
    - RSA < 2048
    - ECDSA < P-256
    - DES, 3DES
    - MD5, SHA-1 for signatures
```

### 2.3 Key Access Control

```yaml
access_control:
  offline_root:
    read: [KeyCustodian]
    use: [KeyCustodian] # Requires quorum
    rotate: [SecurityOfficer, KeyCustodian]

  environment:
    read: [SecurityOfficer, SRE]
    use: [Service]
    rotate: [SecurityOfficer]

  service:
    read: [Service]
    use: [Service]
    rotate: [Automated]

  witness:
    read: [WitnessService]
    use: [WitnessService]
    rotate: [Automated]

  tenant:
    read: [TenantAdmin, SecurityOfficer]
    use: [Service] # For tenant's data only
    rotate: [TenantAdmin, Automated]
```

---

## 3. Compromise Runbook

### 3.1 Detection Signals

| Signal | Severity | Response Time |
|--------|----------|---------------|
| Unexpected key usage pattern | High | 15 minutes |
| Key used from unknown location | Critical | 5 minutes |
| Multiple signature failures | Medium | 30 minutes |
| Key material exposure in logs | Critical | Immediate |
| Unauthorized key access attempt | High | 15 minutes |

### 3.2 Offline Root Key Compromise

```
SEVERITY: CRITICAL
RESPONSE TIME: Immediate

1. IMMEDIATE ACTIONS (0-15 minutes)
   □ Convene emergency key custodian quorum
   □ Notify Security Officer and CISO
   □ Prepare air-gapped signing environment

2. CONTAINMENT (15-60 minutes)
   □ Revoke all environment keys signed by compromised root
   □ Issue CRL update to all endpoints
   □ Halt all production deployments

3. REMEDIATION (1-4 hours)
   □ Generate new offline root key (HSM ceremony)
   □ Sign new environment keys
   □ Distribute new trust anchors to all systems

4. RECOVERY (4-24 hours)
   □ Re-sign all artifacts with new key chain
   □ Verify signature chains on all deployments
   □ Resume normal operations with monitoring

5. POST-INCIDENT (24-72 hours)
   □ Conduct forensic analysis
   □ Update threat model
   □ Document lessons learned
```

### 3.3 Service Key Compromise

```
SEVERITY: HIGH
RESPONSE TIME: ≤ 2 seconds (automated)

1. IMMEDIATE ACTIONS (Automated, 0-2 seconds)
   □ Automatic key rotation triggered
   □ Compromised key added to CRL
   □ Alert sent to Security Operations

2. CONTAINMENT (2-60 seconds)
   □ Verify revocation propagated (≤2s SLA)
   □ Check for unauthorized signatures
   □ Identify affected operations

3. REMEDIATION (1-15 minutes)
   □ Verify new key is active
   □ Re-sign any affected in-flight operations
   □ Verify no data exfiltration occurred

4. RECOVERY (15-60 minutes)
   □ Audit all operations during compromise window
   □ Notify affected tenants if necessary
   □ Document incident
```

### 3.4 Witness Key Compromise

```
SEVERITY: HIGH
RESPONSE TIME: ≤ 5 minutes

1. IMMEDIATE ACTIONS (0-5 minutes)
   □ Revoke compromised witness key
   □ Generate new witness key in separate HSM
   □ Update witness service configuration

2. CONTAINMENT (5-30 minutes)
   □ Identify checkpoints signed with compromised key
   □ Cross-reference with other attestation sources
   □ Mark affected checkpoints for re-attestation

3. REMEDIATION (30 minutes - 2 hours)
   □ Re-attest affected checkpoints with new key
   □ Verify checkpoint chain integrity
   □ Update customer verifier kits with new public key

4. RECOVERY
   □ Verify independent verification still possible
   □ Notify affected tenants
   □ Document incident
```

---

## 4. Revocation Propagation

### 4.1 SLA Requirements

Per Blueprint v6.1 §2.5: **Revocation must take effect within ≤ 2 seconds**

### 4.2 Propagation Mechanism

```
┌─────────────┐    Revocation    ┌─────────────┐
│   Control   │ ──────Event────► │ CRL Service │
│    Plane    │                  │             │
└─────────────┘                  └──────┬──────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
             ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
             │ Orchestrator│     │   Runtime   │     │   Witness   │
             │             │     │    Guard    │     │   Service   │
             └─────────────┘     └─────────────┘     └─────────────┘
```

### 4.3 CRL Service Configuration

```yaml
crl_service:
  update_interval_ms: 100  # Check for updates every 100ms
  propagation_sla_ms: 2000  # Must propagate within 2s

  distribution:
    method: push  # Push updates to subscribers
    protocol: gRPC streaming
    fallback: HTTP polling (500ms interval)

  caching:
    enabled: true
    ttl_seconds: 1  # Very short TTL for revocation entries

  monitoring:
    propagation_latency_histogram: true
    alert_threshold_ms: 1500  # Alert if approaching SLA
```

### 4.4 Revocation Verification

All services must verify key status before use:

```python
def verify_key_not_revoked(key_id: str) -> bool:
    """
    Verify key is not in CRL.
    Must complete within 100ms.
    """
    # Check local cache first (updated via push)
    if crl_cache.is_revoked(key_id):
        return False

    # Verify cache is fresh (within 2s)
    if crl_cache.age_ms() > 2000:
        # Force refresh
        crl_cache.refresh()
        if crl_cache.is_revoked(key_id):
            return False

    return True
```

---

## 5. Audit Logging

### 5.1 Key Operation Events

All key operations must be logged:

```json
{
  "event_type": "KEY_OPERATION",
  "timestamp": "2026-01-11T12:00:00Z",
  "operation": "SIGN|VERIFY|ROTATE|REVOKE|GENERATE",
  "key_id": "key-abc123",
  "key_type": "SERVICE|WITNESS|ENVIRONMENT|TENANT",
  "actor": {
    "type": "SERVICE|OPERATOR",
    "id": "spiffe://frostgate/service/control-plane"
  },
  "result": "SUCCESS|FAILURE",
  "metadata": {
    "subject_hash": "sha256:...",
    "algorithm": "ES256"
  }
}
```

### 5.2 Retention

| Event Type | Retention Period |
|------------|------------------|
| Key generation | 7 years |
| Key rotation | 7 years |
| Key revocation | 7 years |
| Signature operations | 1 year |
| Access attempts (failed) | 2 years |

---

## 6. Key Ceremony Procedures

### 6.1 Root Key Generation

```
CEREMONY: Root Key Generation
PARTICIPANTS: 5 Key Custodians, Security Officer, Witness
LOCATION: Secure facility (SCIF or equivalent)

Prerequisites:
□ Air-gapped HSM prepared
□ All custodians present with credentials
□ Video recording equipment ready
□ Ceremony script distributed

Procedure:
1. Security Officer initiates ceremony
2. HSM powered on in air-gapped environment
3. 3-of-5 custodians authenticate to HSM
4. Key generation command executed
5. Public key exported to USB (verified)
6. HSM powered down and secured
7. Key shards distributed to custodians
8. Ceremony log signed by all participants
```

### 6.2 Environment Key Rotation

```
CEREMONY: Environment Key Rotation
PARTICIPANTS: Security Officer, SRE Lead
FREQUENCY: Quarterly

Procedure:
1. Schedule rotation window
2. Generate new environment key in HSM
3. Sign new key with root key (requires custodian quorum)
4. Deploy new key to signing services
5. Verify new key operational
6. Add old key to rotation-out schedule (7-day grace)
7. Remove old key after grace period
```

---

## References

- Blueprint v6.1 §5.3 (Key Management)
- Blueprint v6.1 §5.4 (Signatures and Dual Attestation)
- Blueprint v6.1 §2.5 (Scoped Revocation)
- NIST SP 800-57 (Key Management Recommendations)
- FIPS 140-3 (Security Requirements for Cryptographic Modules)
