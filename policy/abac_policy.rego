# Frost Gate Spear - ABAC/SoD/Step-up Policy
#
# Implements v6.1 Blueprint requirements:
# - Attribute-Based Access Control (ABAC)
# - Separation of Duties (SoD) enforcement
# - Step-up authentication requirements
#
# This policy MUST be evaluated in the governance preflight flow.
# Fail closed: any evaluation error or missing data results in DENY.

package frostgate.abac

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default deny - fail closed
default allow := false
default sod_violation := false
default stepup_required := false

# Required roles by risk tier
required_roles_by_tier := {
    1: ["Security"],
    2: ["Security", "Product"],
    3: ["Security", "Product", "AO"]
}

# Additional roles by classification level
classification_roles := {
    "CUI": ["GovCompliance"],
    "SECRET": ["GovCompliance", "AO"],
    "TOPSECRET": ["GovCompliance", "AO", "CISO"]
}

# Mode-specific role requirements
mode_roles := {
    "mission": ["MissionOwner"],
    "LIVE_GUARDED": ["SecurityLead"],
    "LIVE_AUTONOMOUS": ["SecurityLead", "AO"]
}

# Actions requiring step-up authentication
stepup_actions := {
    "destructive_operation",
    "scope_expansion",
    "credential_access",
    "classification_change",
    "ao_approval",
    "emergency_stop_override"
}

# SoD incompatible role pairs
sod_incompatible := {
    ["approver", "executor"],
    ["security_reviewer", "developer"],
    ["ao", "mission_executor"]
}

# =============================================================================
# ABAC Access Control
# =============================================================================

# Allow action if all attribute checks pass
allow if {
    # Subject attributes match requirements
    subject_authorized

    # Resource attributes permit access
    resource_accessible

    # Environmental conditions met
    environment_valid

    # Action is permitted for subject's roles
    action_permitted

    # No SoD violations
    not sod_violation

    # Step-up satisfied if required
    stepup_satisfied
}

# Subject authorization checks
subject_authorized if {
    # Subject has required clearance level
    input.subject.clearance_level >= input.resource.required_clearance

    # Subject is not suspended or revoked
    not input.subject.status in ["suspended", "revoked"]

    # Subject's session is valid
    input.subject.session.valid == true
    input.subject.session.expires_at > time.now_ns() / 1000000000
}

# Resource accessibility checks
resource_accessible if {
    # Resource classification <= subject clearance
    classification_level(input.resource.classification) <= classification_level(input.subject.clearance_level)

    # Resource is within subject's authorized scope
    input.resource.scope_id in input.subject.authorized_scopes
}

# Classification level ordering
classification_level(level) := 0 if level == "UNCLASS"
classification_level(level) := 1 if level == "CUI"
classification_level(level) := 2 if level == "SECRET"
classification_level(level) := 3 if level == "TOPSECRET"
classification_level(level) := -1 if not level in ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]

# Environmental condition checks
environment_valid if {
    # Time is within allowed window
    input.environment.current_time >= input.policy.time_window.start
    input.environment.current_time <= input.policy.time_window.end

    # Network zone is authorized
    input.environment.network_zone in input.policy.allowed_network_zones
}

# Action permission check
action_permitted if {
    # Subject has at least one role that permits the action
    some role in input.subject.roles
    action_allowed_for_role(input.action.type, role)
}

# Role-based action permissions
action_allowed_for_role(action, role) if {
    role == "AO"
    # AO can perform any action
}

action_allowed_for_role(action, role) if {
    role == "Security"
    action in ["review", "approve", "audit", "monitor"]
}

action_allowed_for_role(action, role) if {
    role == "Operator"
    action in ["execute", "monitor", "pause", "resume"]
}

action_allowed_for_role(action, role) if {
    role == "Viewer"
    action in ["view", "audit"]
}

# =============================================================================
# Separation of Duties (SoD) Enforcement
# =============================================================================

# Check for SoD violations
sod_violation if {
    # Check if executor is also an approver for high-risk operations
    input.campaign.risk_tier >= 2
    input.campaign.mode in ["LIVE_GUARDED", "LIVE_AUTONOMOUS", "mission"]

    # Executor ID matches any approver ID
    some approval in input.approvals
    approval.approver_id == input.executor_id
}

sod_violation if {
    # Check incompatible role pairs
    some pair in sod_incompatible
    pair[0] in input.subject.active_roles
    pair[1] in input.subject.active_roles
}

# SoD violation details
sod_violations contains violation if {
    input.campaign.risk_tier >= 2
    input.campaign.mode in ["LIVE_GUARDED", "LIVE_AUTONOMOUS", "mission"]
    some approval in input.approvals
    approval.approver_id == input.executor_id

    violation := {
        "type": "EXECUTOR_IS_APPROVER",
        "executor_id": input.executor_id,
        "approver_id": approval.approver_id,
        "role": approval.role,
        "severity": "CRITICAL"
    }
}

sod_violations contains violation if {
    some pair in sod_incompatible
    pair[0] in input.subject.active_roles
    pair[1] in input.subject.active_roles

    violation := {
        "type": "INCOMPATIBLE_ROLES",
        "roles": pair,
        "severity": "HIGH"
    }
}

# =============================================================================
# Step-up Authentication
# =============================================================================

# Determine if step-up is required
stepup_required if {
    input.action.type in stepup_actions
}

stepup_required if {
    # High-risk tier always requires step-up for non-SIM modes
    input.campaign.risk_tier >= 3
    input.campaign.mode != "SIM"
}

stepup_required if {
    # Classified operations require step-up
    input.resource.classification in ["SECRET", "TOPSECRET"]
    input.action.type in ["execute", "approve", "modify"]
}

# Check if step-up is satisfied
stepup_satisfied if {
    not stepup_required
}

stepup_satisfied if {
    stepup_required
    input.subject.stepup_auth.completed == true
    input.subject.stepup_auth.method in ["hardware_token", "biometric", "dual_approval"]
    input.subject.stepup_auth.timestamp > (time.now_ns() / 1000000000) - 300  # Within 5 minutes
}

# Step-up requirements details
stepup_requirements := {
    "required": stepup_required,
    "methods_accepted": ["hardware_token", "biometric", "dual_approval"],
    "reason": stepup_reason
}

stepup_reason := "High-risk action requires step-up" if {
    input.action.type in stepup_actions
}

stepup_reason := "Risk tier 3 requires step-up for non-SIM modes" if {
    input.campaign.risk_tier >= 3
    input.campaign.mode != "SIM"
}

stepup_reason := "Classified operation requires step-up" if {
    input.resource.classification in ["SECRET", "TOPSECRET"]
}

stepup_reason := "Not required" if {
    not stepup_required
}

# =============================================================================
# Required Approvals Validation
# =============================================================================

# Get all required roles for the campaign
required_roles contains role if {
    tier_roles := required_roles_by_tier[input.campaign.risk_tier]
    role := tier_roles[_]
}

required_roles contains role if {
    class_roles := classification_roles[input.campaign.classification_level]
    role := class_roles[_]
}

required_roles contains role if {
    mode_specific := mode_roles[input.campaign.mode]
    role := mode_specific[_]
}

# Get present approval roles
present_roles contains role if {
    some approval in input.approvals
    approval.valid == true
    approval.expires_at > time.now_ns() / 1000000000
    role := approval.role
}

# Missing required roles
missing_roles := required_roles - present_roles

# Approval validation result
approvals_valid if {
    count(missing_roles) == 0
}

approval_issues contains issue if {
    some role in missing_roles
    issue := {
        "type": "MISSING_APPROVAL",
        "role": role,
        "required_for": sprintf("risk_tier=%d, classification=%s, mode=%s", [
            input.campaign.risk_tier,
            input.campaign.classification_level,
            input.campaign.mode
        ])
    }
}

approval_issues contains issue if {
    some approval in input.approvals
    approval.expires_at <= time.now_ns() / 1000000000
    issue := {
        "type": "EXPIRED_APPROVAL",
        "role": approval.role,
        "approver_id": approval.approver_id,
        "expired_at": approval.expires_at
    }
}

# =============================================================================
# Decision Output
# =============================================================================

# Combined decision output
decision := {
    "allow": allow,
    "sod_violation": sod_violation,
    "sod_violations": sod_violations,
    "stepup_required": stepup_required,
    "stepup_satisfied": stepup_satisfied,
    "stepup_requirements": stepup_requirements,
    "approvals_valid": approvals_valid,
    "missing_roles": missing_roles,
    "approval_issues": approval_issues,
    "failure_codes": failure_codes
}

# Collect all failure codes
failure_codes contains code if {
    not subject_authorized
    code := "ABAC.SUBJECT.UNAUTHORIZED"
}

failure_codes contains code if {
    not resource_accessible
    code := "ABAC.RESOURCE.INACCESSIBLE"
}

failure_codes contains code if {
    not environment_valid
    code := "ABAC.ENVIRONMENT.INVALID"
}

failure_codes contains code if {
    not action_permitted
    code := "ABAC.ACTION.NOT_PERMITTED"
}

failure_codes contains code if {
    sod_violation
    code := "ABAC.SOD.VIOLATION"
}

failure_codes contains code if {
    stepup_required
    not stepup_satisfied
    code := "ABAC.STEPUP.REQUIRED"
}

failure_codes contains code if {
    not approvals_valid
    code := "ABAC.APPROVALS.MISSING"
}
