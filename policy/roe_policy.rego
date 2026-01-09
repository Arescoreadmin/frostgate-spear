# Frost Gate Spear - Rules of Engagement (ROE) Policy
# OPA Rego Policy for ROE Enforcement
# Version: 1.0.0

package frostgate.roe

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default deny
default allow := false
default violation := []

# -----------------------------------------------------------------------------
# ROE Configuration Schema
# -----------------------------------------------------------------------------
# Expected input structure:
# {
#   "mission": { "id", "type", "classification_level", "risk_tier", "roe" },
#   "action": { "type", "target", "tool", "timestamp" },
#   "context": { "operator", "approvals", "environment" }
# }

# -----------------------------------------------------------------------------
# Classification Levels
# -----------------------------------------------------------------------------
classification_levels := ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]

classification_rank := {
    "UNCLASS": 0,
    "CUI": 1,
    "SECRET": 2,
    "TOPSECRET": 3
}

# -----------------------------------------------------------------------------
# Risk Tiers
# -----------------------------------------------------------------------------
# Tier 1: Low risk, minimal impact potential
# Tier 2: Medium risk, moderate impact potential
# Tier 3: High risk, significant impact potential (requires AO approval)

risk_tiers := [1, 2, 3]

# -----------------------------------------------------------------------------
# Core ROE Enforcement Rules
# -----------------------------------------------------------------------------

# Allow action if all ROE constraints are satisfied
allow if {
    valid_mission
    valid_action
    within_time_window
    within_scope
    tool_permitted
    target_permitted
    risk_tier_approved
    classification_compliant
    not exceeds_alert_footprint
    not exceeds_blast_radius
}

# -----------------------------------------------------------------------------
# Mission Validation
# -----------------------------------------------------------------------------

valid_mission if {
    input.mission.id != ""
    input.mission.type in allowed_mission_types
    input.mission.classification_level in classification_levels
    input.mission.risk_tier in risk_tiers
    input.mission.roe != null
}

allowed_mission_types := [
    "reconnaissance",
    "vulnerability_assessment",
    "penetration_test",
    "red_team",
    "purple_team",
    "adversary_emulation",
    "training",
    "simulation"
]

# -----------------------------------------------------------------------------
# Action Validation
# -----------------------------------------------------------------------------

valid_action if {
    input.action.type != ""
    input.action.target != null
    input.action.timestamp != ""
}

# -----------------------------------------------------------------------------
# Time Window Enforcement
# -----------------------------------------------------------------------------

within_time_window if {
    not input.mission.roe.time_restrictions
}

within_time_window if {
    input.mission.roe.time_restrictions
    current_time := time.now_ns()
    start_time := time.parse_rfc3339_ns(input.mission.roe.valid_from)
    end_time := time.parse_rfc3339_ns(input.mission.roe.valid_to)
    current_time >= start_time
    current_time <= end_time
}

# -----------------------------------------------------------------------------
# Scope Enforcement
# -----------------------------------------------------------------------------

within_scope if {
    input.action.target.asset in input.mission.roe.allowed_assets
}

within_scope if {
    target_in_network(input.action.target.network, input.mission.roe.allowed_networks)
}

target_in_network(target_net, allowed_nets) if {
    some net in allowed_nets
    net_contains(net, target_net)
}

net_contains(cidr, target) := true if {
    # Simplified network containment check
    cidr == target
}

# -----------------------------------------------------------------------------
# Tool Permission Enforcement
# -----------------------------------------------------------------------------

tool_permitted if {
    input.action.tool in input.mission.roe.allowed_tools
}

tool_permitted if {
    tool_category := get_tool_category(input.action.tool)
    tool_category in input.mission.roe.allowed_tool_categories
    not input.action.tool in input.mission.roe.disallowed_tools
}

get_tool_category(tool) := category if {
    tool_categories[tool] = category
}

get_tool_category(tool) := "unknown" if {
    not tool_categories[tool]
}

tool_categories := {
    "nmap": "reconnaissance",
    "masscan": "reconnaissance",
    "shodan": "reconnaissance",
    "nikto": "vulnerability_scan",
    "nessus": "vulnerability_scan",
    "openvas": "vulnerability_scan",
    "metasploit": "exploitation",
    "cobalt_strike": "exploitation",
    "mimikatz": "credential_access",
    "bloodhound": "discovery",
    "impacket": "lateral_movement",
    "psexec": "lateral_movement",
    "exfil_tool": "exfiltration"
}

# -----------------------------------------------------------------------------
# Target Permission Enforcement
# -----------------------------------------------------------------------------

target_permitted if {
    not input.action.target.asset in input.mission.roe.disallowed_assets
    not target_is_critical(input.action.target)
}

target_permitted if {
    target_is_critical(input.action.target)
    input.mission.roe.critical_systems_authorized
    has_ao_approval
}

target_is_critical(target) if {
    target.criticality == "high"
}

target_is_critical(target) if {
    target.asset in critical_system_patterns
}

critical_system_patterns := [
    "domain_controller",
    "pki_server",
    "scada",
    "ics",
    "medical_device",
    "safety_system"
]

# -----------------------------------------------------------------------------
# Risk Tier Approval
# -----------------------------------------------------------------------------

risk_tier_approved if {
    input.mission.risk_tier <= 2
}

risk_tier_approved if {
    input.mission.risk_tier == 3
    has_ao_approval
}

has_ao_approval if {
    some approval in input.context.approvals
    approval.role == "AO"
    approval.valid
    approval.scope_hash == input.mission.roe.scope_hash
}

# -----------------------------------------------------------------------------
# Classification Compliance
# -----------------------------------------------------------------------------

classification_compliant if {
    action_classification := get_action_classification(input.action)
    mission_rank := classification_rank[input.mission.classification_level]
    action_rank := classification_rank[action_classification]
    action_rank <= mission_rank
}

get_action_classification(action) := action.classification_level if {
    action.classification_level
}

get_action_classification(action) := "UNCLASS" if {
    not action.classification_level
}

# -----------------------------------------------------------------------------
# Alert Footprint Cap
# -----------------------------------------------------------------------------

exceeds_alert_footprint if {
    input.mission.roe.alert_footprint_cap
    input.context.current_alert_count > input.mission.roe.alert_footprint_cap
}

# -----------------------------------------------------------------------------
# Blast Radius Enforcement
# -----------------------------------------------------------------------------

exceeds_blast_radius if {
    input.mission.roe.blast_radius_cap
    input.action.estimated_impact > input.mission.roe.blast_radius_cap
}

# -----------------------------------------------------------------------------
# Violation Collection
# -----------------------------------------------------------------------------

violation contains msg if {
    not valid_mission
    msg := "Invalid or incomplete mission definition"
}

violation contains msg if {
    not valid_action
    msg := "Invalid or incomplete action definition"
}

violation contains msg if {
    input.mission.roe.time_restrictions
    not within_time_window
    msg := "Action attempted outside authorized time window"
}

violation contains msg if {
    not within_scope
    msg := sprintf("Target %v is outside authorized scope", [input.action.target.asset])
}

violation contains msg if {
    not tool_permitted
    msg := sprintf("Tool %v is not permitted under current ROE", [input.action.tool])
}

violation contains msg if {
    not target_permitted
    msg := sprintf("Target %v is not permitted or requires additional authorization", [input.action.target.asset])
}

violation contains msg if {
    input.mission.risk_tier == 3
    not has_ao_approval
    msg := "Risk tier 3 mission requires AO approval"
}

violation contains msg if {
    not classification_compliant
    msg := "Action classification exceeds mission classification level"
}

violation contains msg if {
    exceeds_alert_footprint
    msg := sprintf("Alert footprint cap exceeded: %v > %v", [input.context.current_alert_count, input.mission.roe.alert_footprint_cap])
}

violation contains msg if {
    exceeds_blast_radius
    msg := sprintf("Estimated impact exceeds blast radius cap: %v > %v", [input.action.estimated_impact, input.mission.roe.blast_radius_cap])
}

# -----------------------------------------------------------------------------
# Lateral Movement Control (No Autonomous Scope Expansion)
# -----------------------------------------------------------------------------

lateral_movement_allowed if {
    input.action.type == "lateral_movement"
    input.mission.roe.lateral_movement_authorized
    input.action.target.asset in input.mission.roe.lateral_movement_targets
}

violation contains msg if {
    input.action.type == "lateral_movement"
    not lateral_movement_allowed
    msg := "Lateral movement not authorized or target not in approved list"
}

# -----------------------------------------------------------------------------
# Live Exploitation Control
# -----------------------------------------------------------------------------

exploitation_allowed if {
    input.action.type == "exploitation"
    input.mission.risk_tier <= 2
    input.mission.classification_level in ["UNCLASS", "CUI"]
}

exploitation_allowed if {
    input.action.type == "exploitation"
    has_ao_approval
}

violation contains msg if {
    input.action.type == "exploitation"
    not exploitation_allowed
    msg := "Live exploitation requires AO approval for risk tier 3 or classification > CUI"
}

# -----------------------------------------------------------------------------
# Destructive Operations Control
# -----------------------------------------------------------------------------

destructive_ops_allowed if {
    input.action.destructive == true
    has_ao_approval
    input.mission.roe.destructive_ops_authorized
}

violation contains msg if {
    input.action.destructive == true
    not destructive_ops_allowed
    msg := "Destructive operations require AO signature and explicit ROE authorization"
}
