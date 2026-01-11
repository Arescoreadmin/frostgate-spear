# Frost Gate Spear - Canonical Scope Linting Policy
#
# Implements v6.1 Blueprint requirements:
# - Canonical scope validation (not just schema presence)
# - Strongly-typed asset IDs (no free-text)
# - Boundary validation (networks, domains)
# - Time window limits
# - Authorization reference requirements
# - Runtime scope drift detection
#
# This policy is enforced at:
# 1. Preflight validation (schema + semantic checks)
# 2. Runtime (drift detection per action)

package frostgate.scope

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default results
default scope_valid := false
default drift_detected := false

# Maximum time window duration in hours
max_time_window_hours := 72

# Asset ID patterns (strongly typed)
asset_id_patterns := {
    "HOST": "^HOST-[A-Z0-9]{9,}$",
    "IP": "^IP-([0-9]{1,3}\\.){3}[0-9]{1,3}$",
    "CIDR": "^CIDR-([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$",
    "DOMAIN": "^DOMAIN-[a-z0-9.-]+$",
    "URL": "^URL-https?://[a-z0-9.-]+.*$",
    "SERVICE": "^SVC-[A-Z0-9_-]+$",
    "CONTAINER": "^CTR-[a-f0-9]{12,}$",
    "CLOUD_RESOURCE": "^(AWS|GCP|AZURE)-[A-Z0-9_-]+$"
}

# Valid environments
valid_environments := {"SIM", "LAB", "CANARY", "SHADOW", "PROD", "MISSION"}

# Environments requiring authorization_ref
auth_required_environments := {"PROD", "MISSION"}

# =============================================================================
# SCOPE VALIDATION (Preflight)
# =============================================================================

# Scope is valid if all checks pass
scope_valid if {
    scope_id_valid
    assets_valid
    boundaries_valid
    time_window_valid
    environment_valid
    authorization_valid
    scope_hash_valid
    contact_valid
}

# Validate scope_id is a proper UUID
scope_id_valid if {
    input.scope.scope_id != null
    regex.match("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", lower(input.scope.scope_id))
}

# Validate all assets have strongly-typed IDs
assets_valid if {
    count(input.scope.assets) > 0
    every asset in input.scope.assets {
        asset_id_valid(asset)
    }
}

# Check if asset ID matches expected pattern
asset_id_valid(asset) if {
    asset.asset_id != null
    asset.asset_type != null
    pattern := asset_id_patterns[asset.asset_type]
    regex.match(pattern, asset.asset_id)
}

# Allow generic pattern for unknown types but require prefix
asset_id_valid(asset) if {
    asset.asset_id != null
    not asset.asset_type in object.keys(asset_id_patterns)
    regex.match("^[A-Z]+-[A-Za-z0-9_-]+$", asset.asset_id)
}

# Validate boundaries exist and are properly formatted
boundaries_valid if {
    input.scope.boundaries != null
    boundaries_have_content
    networks_valid
    domains_valid
}

boundaries_have_content if {
    count(input.scope.boundaries.networks) > 0
}

boundaries_have_content if {
    count(input.scope.boundaries.domains) > 0
}

# Validate network CIDRs
networks_valid if {
    every network in input.scope.boundaries.networks {
        network.cidr != null
        # Basic CIDR format check
        regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", network.cidr)
    }
}

networks_valid if {
    count(input.scope.boundaries.networks) == 0
}

# Validate domains
domains_valid if {
    every domain in input.scope.boundaries.domains {
        domain.domain != null
        # Basic domain format check
        regex.match("^[a-zA-Z0-9][a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}$", domain.domain)
    }
}

domains_valid if {
    count(input.scope.boundaries.domains) == 0
}

# Validate time window
time_window_valid if {
    input.scope.time_window != null
    input.scope.time_window.start != null
    input.scope.time_window.end != null

    # Parse times and check duration
    start_ns := time.parse_rfc3339_ns(input.scope.time_window.start)
    end_ns := time.parse_rfc3339_ns(input.scope.time_window.end)

    # End must be after start
    end_ns > start_ns

    # Duration must not exceed max
    duration_hours := (end_ns - start_ns) / (1000000000 * 3600)
    duration_hours <= max_time_window_hours
}

# Validate environment
environment_valid if {
    input.scope.environment in valid_environments
}

# Validate authorization reference
authorization_valid if {
    not input.scope.environment in auth_required_environments
}

authorization_valid if {
    input.scope.environment in auth_required_environments
    input.scope.authorization_ref != null
    input.scope.authorization_ref.ref_id != null
    input.scope.authorization_ref.ref_id != ""
    input.scope.authorization_ref.type != null
}

# Validate scope hash matches computed hash
scope_hash_valid if {
    input.scope.scope_hash != null
    # Hash verification is done by the validator module
    # This just checks the field exists
    startswith(input.scope.scope_hash, "sha256:")
}

# Validate contact information
contact_valid if {
    input.scope.contact_on_call != null
    input.scope.contact_on_call.primary != null
    input.scope.contact_on_call.primary.email != null
}

contact_valid if {
    input.scope.environment == "SIM"
}

# =============================================================================
# SCOPE VALIDATION ISSUES
# =============================================================================

scope_issues contains issue if {
    not scope_id_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.SCOPE_ID",
        "message": "scope_id is missing or not a valid UUID"
    }
}

scope_issues contains issue if {
    count(input.scope.assets) == 0
    issue := {
        "rule": "PREFLIGHT.SCOPE.NO_ASSETS",
        "message": "Scope must contain at least one asset"
    }
}

scope_issues contains issue if {
    some asset in input.scope.assets
    not asset_id_valid(asset)
    issue := {
        "rule": "PREFLIGHT.SCOPE.ASSET_ID_FORMAT",
        "message": sprintf("Asset ID '%s' does not match required pattern for type '%s'", [asset.asset_id, asset.asset_type])
    }
}

scope_issues contains issue if {
    not boundaries_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.BOUNDARIES",
        "message": "Scope boundaries are invalid or missing"
    }
}

scope_issues contains issue if {
    input.scope.time_window == null
    issue := {
        "rule": "PREFLIGHT.SCOPE.TIME_WINDOW",
        "message": "Time window is required"
    }
}

scope_issues contains issue if {
    input.scope.time_window != null
    not time_window_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.TIME_WINDOW_DURATION",
        "message": sprintf("Time window exceeds maximum of %d hours", [max_time_window_hours])
    }
}

scope_issues contains issue if {
    not environment_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.ENVIRONMENT",
        "message": sprintf("Invalid environment '%s'. Must be one of: %v", [input.scope.environment, valid_environments])
    }
}

scope_issues contains issue if {
    not authorization_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.AUTHORIZATION_REF",
        "message": sprintf("Environment '%s' requires authorization_ref", [input.scope.environment])
    }
}

scope_issues contains issue if {
    not scope_hash_valid
    issue := {
        "rule": "PREFLIGHT.SCOPE.SCOPE_HASH",
        "message": "scope_hash is missing or invalid format"
    }
}

scope_issues contains issue if {
    not contact_valid
    input.scope.environment != "SIM"
    issue := {
        "rule": "PREFLIGHT.SCOPE.CONTACT",
        "message": "contact_on_call with primary email is required for non-SIM environments"
    }
}

# =============================================================================
# SCOPE DRIFT DETECTION (Runtime)
# =============================================================================

# Detect drift when actions target unauthorized scope
drift_detected if {
    count(drift_violations) > 0
}

# Calculate drift severity (P1-P5)
drift_severity := severity if {
    drift_percentage := drift_percentage_calc
    severity := calculate_severity(drift_percentage)
}

drift_percentage_calc := percentage if {
    total := count(input.executed_actions)
    total > 0
    drifted := count(drift_violations)
    percentage := (drifted * 100) / total
}

drift_percentage_calc := 0 if {
    count(input.executed_actions) == 0
}

calculate_severity(pct) := "P1" if { pct <= 5 }
calculate_severity(pct) := "P2" if { pct > 5; pct <= 10 }
calculate_severity(pct) := "P3" if { pct > 10; pct <= 20 }
calculate_severity(pct) := "P4" if { pct > 20; pct <= 40 }
calculate_severity(pct) := "P5" if { pct > 40 }

# Collect drift violations
drift_violations contains violation if {
    some action in input.executed_actions
    action.target_id != null
    not target_in_scope(action.target_id)
    violation := {
        "action_id": action.action_id,
        "target_id": action.target_id,
        "type": "ASSET_OUT_OF_SCOPE"
    }
}

drift_violations contains violation if {
    some action in input.executed_actions
    action.target_network != null
    not network_in_scope(action.target_network)
    violation := {
        "action_id": action.action_id,
        "target_network": action.target_network,
        "type": "NETWORK_OUT_OF_SCOPE"
    }
}

drift_violations contains violation if {
    some action in input.executed_actions
    action.target_domain != null
    not domain_in_scope(action.target_domain)
    violation := {
        "action_id": action.action_id,
        "target_domain": action.target_domain,
        "type": "DOMAIN_OUT_OF_SCOPE"
    }
}

# Check if target is in approved scope
target_in_scope(target_id) if {
    some asset in input.approved_scope.assets
    asset.asset_id == target_id
}

# Check if network is in approved scope
network_in_scope(ip) if {
    some network in input.approved_scope.boundaries.networks
    net.cidr_contains(network.cidr, ip)
}

# Check if domain is in approved scope
domain_in_scope(domain) if {
    some approved in input.approved_scope.boundaries.domains
    domain_matches(domain, approved.domain)
}

# Domain matching (exact or subdomain)
domain_matches(target, approved) if {
    target == approved
}

domain_matches(target, approved) if {
    endswith(target, concat("", [".", approved]))
}

# =============================================================================
# DRIFT RESPONSE RECOMMENDATIONS
# =============================================================================

# Recommended action based on severity
drift_response := response if {
    drift_detected
    drift_severity in ["P1"]
    response := {
        "action": "ALERT_ONLY",
        "message": "Minor drift detected - alerting only",
        "severity": drift_severity,
        "drift_percentage": drift_percentage_calc
    }
}

drift_response := response if {
    drift_detected
    drift_severity in ["P2", "P3", "P4", "P5"]
    response := {
        "action": "HALT_AND_REVOKE",
        "message": "Significant drift detected - halting execution and revoking permit",
        "severity": drift_severity,
        "drift_percentage": drift_percentage_calc,
        "violations": drift_violations
    }
}

drift_response := response if {
    not drift_detected
    response := {
        "action": "NONE",
        "message": "No drift detected",
        "severity": "NONE",
        "drift_percentage": 0
    }
}

# =============================================================================
# COMBINED DECISION OUTPUT
# =============================================================================

decision := {
    "scope_valid": scope_valid,
    "scope_issues": scope_issues,
    "drift_detected": drift_detected,
    "drift_severity": drift_severity,
    "drift_violations": drift_violations,
    "drift_response": drift_response
}
