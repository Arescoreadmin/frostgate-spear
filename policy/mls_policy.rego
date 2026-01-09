# Frost Gate Spear - Multi-Level Security (MLS) Policy
# OPA Rego Policy for Classification Ring Enforcement
# Version: 1.0.0

package frostgate.mls

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default deny cross-ring operations
default allowed := false
default mls_violations := []

# -----------------------------------------------------------------------------
# Classification Rings
# -----------------------------------------------------------------------------

rings := ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]

ring_level := {
    "UNCLASS": 0,
    "CUI": 1,
    "SECRET": 2,
    "TOPSECRET": 3
}

# -----------------------------------------------------------------------------
# Core MLS Rules
# -----------------------------------------------------------------------------

# Bell-LaPadula: No read up, no write down (with exceptions for authorized flows)
allowed if {
    valid_read_operation
    valid_write_operation
    no_unauthorized_cross_ring
    artifacts_labeled
    gradients_isolated
}

# -----------------------------------------------------------------------------
# Read Operations (No Read Up)
# -----------------------------------------------------------------------------

valid_read_operation if {
    not input.operation.type == "read"
}

valid_read_operation if {
    input.operation.type == "read"
    subject_level := ring_level[input.subject.classification]
    object_level := ring_level[input.object.classification]
    subject_level >= object_level
}

mls_violations contains msg if {
    input.operation.type == "read"
    subject_level := ring_level[input.subject.classification]
    object_level := ring_level[input.object.classification]
    subject_level < object_level
    msg := sprintf("Read up violation: %s subject cannot read %s object",
        [input.subject.classification, input.object.classification])
}

# -----------------------------------------------------------------------------
# Write Operations (No Write Down without Authorization)
# -----------------------------------------------------------------------------

valid_write_operation if {
    not input.operation.type == "write"
}

valid_write_operation if {
    input.operation.type == "write"
    subject_level := ring_level[input.subject.classification]
    object_level := ring_level[input.object.classification]
    subject_level <= object_level
}

valid_write_operation if {
    input.operation.type == "write"
    subject_level := ring_level[input.subject.classification]
    object_level := ring_level[input.object.classification]
    subject_level > object_level
    input.operation.declassification_authorized
    input.operation.sanitized
}

mls_violations contains msg if {
    input.operation.type == "write"
    subject_level := ring_level[input.subject.classification]
    object_level := ring_level[input.object.classification]
    subject_level > object_level
    not input.operation.declassification_authorized
    msg := sprintf("Write down violation: %s subject cannot write to %s object without declassification",
        [input.subject.classification, input.object.classification])
}

# -----------------------------------------------------------------------------
# Cross-Ring Data Flow
# -----------------------------------------------------------------------------

no_unauthorized_cross_ring if {
    not input.data_flow
}

no_unauthorized_cross_ring if {
    input.data_flow
    input.data_flow.source_ring == input.data_flow.dest_ring
}

no_unauthorized_cross_ring if {
    input.data_flow
    input.data_flow.source_ring != input.data_flow.dest_ring
    authorized_cross_ring_flow(input.data_flow)
}

authorized_cross_ring_flow(flow) if {
    # Downgrade authorized with sanitization
    ring_level[flow.source_ring] > ring_level[flow.dest_ring]
    flow.sanitization_applied
    flow.declassification_approval != ""
    flow.audit_logged
}

authorized_cross_ring_flow(flow) if {
    # Upgrade is generally allowed (data going to higher classification)
    ring_level[flow.source_ring] < ring_level[flow.dest_ring]
}

mls_violations contains msg if {
    input.data_flow
    input.data_flow.source_ring != input.data_flow.dest_ring
    not authorized_cross_ring_flow(input.data_flow)
    msg := sprintf("Unauthorized cross-ring data flow: %s -> %s",
        [input.data_flow.source_ring, input.data_flow.dest_ring])
}

# -----------------------------------------------------------------------------
# Artifact Labeling
# -----------------------------------------------------------------------------

artifacts_labeled if {
    not input.artifact
}

artifacts_labeled if {
    input.artifact
    input.artifact.classification_label != ""
    input.artifact.classification_label in rings
}

mls_violations contains msg if {
    input.artifact
    input.artifact.classification_label == ""
    msg := sprintf("Artifact %s missing classification label", [input.artifact.id])
}

mls_violations contains msg if {
    input.artifact
    input.artifact.classification_label != ""
    not input.artifact.classification_label in rings
    msg := sprintf("Artifact %s has invalid classification label: %s",
        [input.artifact.id, input.artifact.classification_label])
}

# -----------------------------------------------------------------------------
# Gradient Isolation (FL Ring Protection)
# -----------------------------------------------------------------------------

gradients_isolated if {
    not input.gradient_flow
}

gradients_isolated if {
    input.gradient_flow
    input.gradient_flow.source_ring == input.gradient_flow.dest_ring
}

gradients_isolated if {
    input.gradient_flow
    input.gradient_flow.source_ring != input.gradient_flow.dest_ring
    input.gradient_flow.differential_privacy_applied
    input.gradient_flow.dp_epsilon <= input.policy.max_dp_epsilon
    input.gradient_flow.aggregated
    input.gradient_flow.min_participants >= input.policy.min_fl_participants
}

mls_violations contains msg if {
    input.gradient_flow
    input.gradient_flow.source_ring != input.gradient_flow.dest_ring
    not input.gradient_flow.differential_privacy_applied
    msg := "Cross-ring gradient flow without differential privacy"
}

mls_violations contains msg if {
    input.gradient_flow
    input.gradient_flow.source_ring != input.gradient_flow.dest_ring
    input.gradient_flow.differential_privacy_applied
    input.gradient_flow.dp_epsilon > input.policy.max_dp_epsilon
    msg := sprintf("Cross-ring gradient DP epsilon too high: %.4f > %.4f",
        [input.gradient_flow.dp_epsilon, input.policy.max_dp_epsilon])
}

# -----------------------------------------------------------------------------
# Enclave Isolation
# -----------------------------------------------------------------------------

enclave_isolated if {
    input.enclave.ring in rings
    input.enclave.network_isolated
    input.enclave.process_isolated
    input.enclave.storage_isolated
}

mls_violations contains msg if {
    not input.enclave.network_isolated
    msg := sprintf("Enclave %s network isolation failure", [input.enclave.id])
}

mls_violations contains msg if {
    not input.enclave.process_isolated
    msg := sprintf("Enclave %s process isolation failure", [input.enclave.id])
}

mls_violations contains msg if {
    not input.enclave.storage_isolated
    msg := sprintf("Enclave %s storage isolation failure", [input.enclave.id])
}

# -----------------------------------------------------------------------------
# Execution Ring Constraints
# -----------------------------------------------------------------------------

execution_ring_valid if {
    input.execution.ring == input.mission.classification_level
}

execution_ring_valid if {
    exec_level := ring_level[input.execution.ring]
    mission_level := ring_level[input.mission.classification_level]
    exec_level >= mission_level
}

mls_violations contains msg if {
    exec_level := ring_level[input.execution.ring]
    mission_level := ring_level[input.mission.classification_level]
    exec_level < mission_level
    msg := sprintf("Execution ring %s insufficient for mission classification %s",
        [input.execution.ring, input.mission.classification_level])
}

# -----------------------------------------------------------------------------
# Model Isolation
# -----------------------------------------------------------------------------

model_ring_compliant if {
    input.model.trained_ring == input.model.deployment_ring
}

model_ring_compliant if {
    trained_level := ring_level[input.model.trained_ring]
    deploy_level := ring_level[input.model.deployment_ring]
    # Model can be deployed to same or higher ring
    deploy_level >= trained_level
}

mls_violations contains msg if {
    trained_level := ring_level[input.model.trained_ring]
    deploy_level := ring_level[input.model.deployment_ring]
    deploy_level < trained_level
    msg := sprintf("Model trained at %s cannot be deployed to %s",
        [input.model.trained_ring, input.model.deployment_ring])
}

# -----------------------------------------------------------------------------
# Promotion Ring Validation
# -----------------------------------------------------------------------------

promotion_ring_valid if {
    input.promotion.source_ring == input.promotion.target_ring
}

promotion_ring_valid if {
    # Promotion within same ring across environments
    input.promotion.source_ring == input.promotion.target_ring
    valid_promotion_env(input.promotion.source_env, input.promotion.target_env)
}

valid_promotion_env("simulation", "lab") := true
valid_promotion_env("lab", "canary") := true
valid_promotion_env("canary", "production") := true
valid_promotion_env("canary", "mission") := true

mls_violations contains msg if {
    input.promotion
    input.promotion.source_ring != input.promotion.target_ring
    msg := sprintf("Cross-ring promotion not allowed: %s -> %s",
        [input.promotion.source_ring, input.promotion.target_ring])
}

# -----------------------------------------------------------------------------
# Audit Requirements per Ring
# -----------------------------------------------------------------------------

audit_compliant if {
    input.audit.worm_storage == true
    input.audit.externally_timestamped == true
    input.audit.ring_labeled == true
}

mls_violations contains msg if {
    not input.audit.worm_storage
    msg := "Audit logs must use WORM storage"
}

mls_violations contains msg if {
    not input.audit.externally_timestamped
    msg := "Audit logs must be externally timestamped"
}

mls_violations contains msg if {
    not input.audit.ring_labeled
    msg := "Audit logs must include ring classification labels"
}
