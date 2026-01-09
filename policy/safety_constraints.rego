# Frost Gate Spear - Safety Constraints Policy
# OPA Rego Policy for Safety Enforcement
# Version: 1.0.0

package frostgate.safety

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default deny for safety-critical operations
default safe := false
default safety_violations := []

# -----------------------------------------------------------------------------
# Safety Configuration
# -----------------------------------------------------------------------------

# Forensic completeness threshold (95%)
forensic_completeness_threshold := 0.95

# Replay success threshold (95%)
replay_success_threshold := 0.95

# Impact prediction accuracy threshold (90%)
impact_accuracy_threshold := 0.90

# Maximum concurrent attack operations
max_concurrent_operations := 10

# Deception false-positive rate threshold
deception_fp_threshold := 0.05

# -----------------------------------------------------------------------------
# Core Safety Checks
# -----------------------------------------------------------------------------

safe if {
    forensic_complete
    within_concurrency_limits
    simulation_validated
    no_scope_expansion
    no_cross_ring_contamination
    no_roe_override
    scenario_hash_valid
    binary_signed
}

# -----------------------------------------------------------------------------
# Forensic Completeness
# -----------------------------------------------------------------------------

forensic_complete if {
    input.metrics.forensic_completeness >= forensic_completeness_threshold
}

safety_violations contains msg if {
    input.metrics.forensic_completeness < forensic_completeness_threshold
    msg := sprintf("Forensic completeness below threshold: %.2f < %.2f",
        [input.metrics.forensic_completeness, forensic_completeness_threshold])
}

# -----------------------------------------------------------------------------
# Concurrency Limits
# -----------------------------------------------------------------------------

within_concurrency_limits if {
    input.state.active_operations <= max_concurrent_operations
}

within_concurrency_limits if {
    input.state.active_operations <= input.policy.max_concurrent_operations
}

safety_violations contains msg if {
    limit := object.get(input.policy, "max_concurrent_operations", max_concurrent_operations)
    input.state.active_operations > limit
    msg := sprintf("Concurrent operations exceed limit: %d > %d",
        [input.state.active_operations, limit])
}

# -----------------------------------------------------------------------------
# Simulation Validation (SIM-First)
# -----------------------------------------------------------------------------

simulation_validated if {
    input.promotion.source_environment == "simulation"
    input.promotion.sim_runs >= 1000
    input.promotion.policy_violations == 0
}

simulation_validated if {
    input.context.environment == "simulation"
}

simulation_validated if {
    input.promotion.validated == true
    input.promotion.validation_hash != ""
}

safety_violations contains msg if {
    input.promotion.source_environment == "simulation"
    input.promotion.sim_runs < 1000
    msg := sprintf("Insufficient simulation runs: %d < 1000", [input.promotion.sim_runs])
}

safety_violations contains msg if {
    input.promotion.source_environment == "simulation"
    input.promotion.policy_violations > 0
    msg := sprintf("Policy violations detected in simulation: %d", [input.promotion.policy_violations])
}

# -----------------------------------------------------------------------------
# No Autonomous Scope Expansion
# -----------------------------------------------------------------------------

no_scope_expansion if {
    not input.action.expands_scope
}

no_scope_expansion if {
    input.action.expands_scope
    input.action.scope_expansion_authorized
    scope_expansion_in_roe
}

scope_expansion_in_roe if {
    input.policy.roe.lateral_movement_authorized
    input.action.target in input.policy.roe.lateral_movement_targets
}

safety_violations contains msg if {
    input.action.expands_scope
    not input.action.scope_expansion_authorized
    msg := "Unauthorized scope expansion attempted"
}

safety_violations contains msg if {
    input.action.expands_scope
    input.action.scope_expansion_authorized
    not scope_expansion_in_roe
    msg := "Scope expansion not permitted by ROE"
}

# -----------------------------------------------------------------------------
# No Cross-Ring Contamination (MLS)
# -----------------------------------------------------------------------------

no_cross_ring_contamination if {
    not input.data_flow
}

no_cross_ring_contamination if {
    input.data_flow
    valid_data_flow(input.data_flow)
}

valid_data_flow(flow) if {
    flow.source_ring == flow.destination_ring
}

valid_data_flow(flow) if {
    # Data can flow down (higher to lower classification) with proper controls
    ring_rank[flow.source_ring] > ring_rank[flow.destination_ring]
    flow.sanitized == true
    flow.declassification_authorized == true
}

ring_rank := {
    "UNCLASS": 0,
    "CUI": 1,
    "SECRET": 2,
    "TOPSECRET": 3
}

safety_violations contains msg if {
    input.data_flow
    not valid_data_flow(input.data_flow)
    msg := sprintf("Cross-ring contamination: %s -> %s",
        [input.data_flow.source_ring, input.data_flow.destination_ring])
}

# -----------------------------------------------------------------------------
# No ROE Override by Personas
# -----------------------------------------------------------------------------

no_roe_override if {
    not input.persona
}

no_roe_override if {
    input.persona
    not input.persona.overrides_roe
    not input.persona.overrides_safety
    not input.persona.overrides_policy
}

safety_violations contains msg if {
    input.persona.overrides_roe
    msg := sprintf("Persona %s attempted to override ROE", [input.persona.id])
}

safety_violations contains msg if {
    input.persona.overrides_safety
    msg := sprintf("Persona %s attempted to override safety constraints", [input.persona.id])
}

safety_violations contains msg if {
    input.persona.overrides_policy
    msg := sprintf("Persona %s attempted to override policy envelope", [input.persona.id])
}

# -----------------------------------------------------------------------------
# Scenario Hash Validation
# -----------------------------------------------------------------------------

scenario_hash_valid if {
    not input.scenario
}

scenario_hash_valid if {
    input.scenario
    input.scenario.hash != ""
    input.scenario.hash == input.scenario.computed_hash
}

safety_violations contains msg if {
    input.scenario
    input.scenario.hash != input.scenario.computed_hash
    msg := "Scenario hash mismatch - integrity violation"
}

# -----------------------------------------------------------------------------
# Binary Signature Validation
# -----------------------------------------------------------------------------

binary_signed if {
    not input.binary
}

binary_signed if {
    input.binary
    input.binary.signed == true
    input.binary.signature_valid == true
    input.binary.attestation_hash != ""
}

safety_violations contains msg if {
    input.binary
    not input.binary.signed
    msg := sprintf("Unsigned binary: %s", [input.binary.name])
}

safety_violations contains msg if {
    input.binary
    input.binary.signed
    not input.binary.signature_valid
    msg := sprintf("Invalid signature for binary: %s", [input.binary.name])
}

# -----------------------------------------------------------------------------
# Impact Estimation Validation
# -----------------------------------------------------------------------------

impact_within_bounds if {
    input.action.estimated_impact <= input.policy.roe.blast_radius_cap
}

safety_violations contains msg if {
    input.action.estimated_impact > input.policy.roe.blast_radius_cap
    msg := sprintf("Estimated impact exceeds bounds: %.2f > %.2f",
        [input.action.estimated_impact, input.policy.roe.blast_radius_cap])
}

# -----------------------------------------------------------------------------
# Deception Detection Safety
# -----------------------------------------------------------------------------

deception_safe if {
    not input.deception_metrics
}

deception_safe if {
    input.deception_metrics
    input.deception_metrics.false_positive_rate <= deception_fp_threshold
}

safety_violations contains msg if {
    input.deception_metrics
    input.deception_metrics.false_positive_rate > deception_fp_threshold
    msg := sprintf("Deception false-positive rate too high: %.2f > %.2f",
        [input.deception_metrics.false_positive_rate, deception_fp_threshold])
}

# -----------------------------------------------------------------------------
# Classification Level Modification Prevention
# -----------------------------------------------------------------------------

classification_immutable if {
    not input.action.modifies_classification
}

safety_violations contains msg if {
    input.action.modifies_classification
    msg := "Automated classification level modification is prohibited"
}

# -----------------------------------------------------------------------------
# Promotion Path Validation
# -----------------------------------------------------------------------------

valid_promotion_path if {
    not input.promotion
}

valid_promotion_path if {
    input.promotion
    valid_path(input.promotion.from, input.promotion.to)
}

# Valid promotion paths: SIM -> Lab -> Canary -> Mission/Production
valid_path("simulation", "lab") := true
valid_path("lab", "canary") := true
valid_path("canary", "production") := true
valid_path("canary", "mission") := true

safety_violations contains msg if {
    input.promotion
    not valid_path(input.promotion.from, input.promotion.to)
    msg := sprintf("Invalid promotion path: %s -> %s", [input.promotion.from, input.promotion.to])
}

# -----------------------------------------------------------------------------
# Red Lines - Absolute Prohibitions
# -----------------------------------------------------------------------------

red_line_violations contains msg if {
    input.action.outside_mission_roe
    msg := "RED LINE: Action outside mission ROE"
}

red_line_violations contains msg if {
    input.action.modifies_classification
    input.action.automated
    msg := "RED LINE: Automated classification level modification"
}

red_line_violations contains msg if {
    input.persona
    input.persona.overrides_roe
    msg := "RED LINE: Persona override of ROE"
}

red_line_violations contains msg if {
    input.data_flow
    input.data_flow.cross_ring
    not input.data_flow.authorized
    msg := "RED LINE: Unauthorized cross-ring contamination"
}

red_line_violations contains msg if {
    input.action.destructive
    not input.approvals.ao_signature
    msg := "RED LINE: Destructive operation without AO signature"
}

red_line_violations contains msg if {
    input.scenario
    input.scenario.hash != input.scenario.expected_hash
    msg := "RED LINE: Scenario execution without hash match"
}

red_line_violations contains msg if {
    input.binary
    not input.binary.signed
    msg := "RED LINE: Unsigned binary execution"
}

red_line_violations contains msg if {
    input.binary
    not input.binary.attested
    msg := "RED LINE: Un-attested binary execution"
}
