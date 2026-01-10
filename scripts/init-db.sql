-- Frost Gate Spear Database Initialization
-- PostgreSQL schema for mission tracking and forensics

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Missions table
CREATE TABLE IF NOT EXISTS missions (
    mission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    state VARCHAR(50) NOT NULL DEFAULT 'created',
    classification_level VARCHAR(20) NOT NULL DEFAULT 'UNCLASS',
    mission_type VARCHAR(50),
    risk_tier INTEGER DEFAULT 1,
    persona_id VARCHAR(100),
    policy_envelope JSONB NOT NULL,
    scenario JSONB NOT NULL,
    plan JSONB,
    progress FLOAT DEFAULT 0.0,
    impact_score FLOAT DEFAULT 0.0,
    alerts_generated INTEGER DEFAULT 0,
    scenario_hash VARCHAR(100),
    plan_hash VARCHAR(100),
    lineage_hash VARCHAR(100),
    error TEXT,
    abort_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Action results table
CREATE TABLE IF NOT EXISTS action_results (
    action_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(mission_id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    target VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    duration_ms INTEGER,
    impact_score FLOAT DEFAULT 0.0,
    alerts_generated INTEGER DEFAULT 0,
    output JSONB,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Forensic records table
CREATE TABLE IF NOT EXISTS forensic_records (
    record_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(mission_id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    data JSONB NOT NULL,
    hash VARCHAR(100) NOT NULL,
    previous_hash VARCHAR(100),
    classification_level VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Approvals table
CREATE TABLE IF NOT EXISTS approvals (
    approval_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(mission_id) ON DELETE CASCADE,
    approver_id VARCHAR(100) NOT NULL,
    approver_name VARCHAR(255),
    role VARCHAR(100) NOT NULL,
    signature TEXT NOT NULL,
    scope_hash VARCHAR(100) NOT NULL,
    valid BOOLEAN DEFAULT TRUE,
    expiry TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Gate results table
CREATE TABLE IF NOT EXISTS gate_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(mission_id) ON DELETE CASCADE,
    gate_name VARCHAR(100) NOT NULL,
    passed BOOLEAN NOT NULL,
    criteria JSONB NOT NULL,
    failed_criteria JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- FL rounds table
CREATE TABLE IF NOT EXISTS fl_rounds (
    round_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    round_number INTEGER NOT NULL,
    ring VARCHAR(20) NOT NULL,
    participants INTEGER NOT NULL,
    aggregation_method VARCHAR(50),
    dp_epsilon FLOAT,
    dp_delta FLOAT,
    metrics JSONB,
    lineage_hash VARCHAR(100),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Budget usage table
CREATE TABLE IF NOT EXISTS budget_usage (
    usage_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(100) NOT NULL,
    ring VARCHAR(20) NOT NULL,
    compute_hours_used FLOAT DEFAULT 0,
    api_calls_used INTEGER DEFAULT 0,
    cost_usd_used FLOAT DEFAULT 0,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log table (WORM-style)
CREATE TABLE IF NOT EXISTS audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255),
    resource_type VARCHAR(100),
    resource_id UUID,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    classification_level VARCHAR(20) NOT NULL,
    client_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_missions_state ON missions(state);
CREATE INDEX IF NOT EXISTS idx_missions_classification ON missions(classification_level);
CREATE INDEX IF NOT EXISTS idx_missions_created_at ON missions(created_at);
CREATE INDEX IF NOT EXISTS idx_action_results_mission ON action_results(mission_id);
CREATE INDEX IF NOT EXISTS idx_forensic_records_mission ON forensic_records(mission_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for missions table
DROP TRIGGER IF EXISTS trigger_missions_updated_at ON missions;
CREATE TRIGGER trigger_missions_updated_at
    BEFORE UPDATE ON missions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- Trigger for budget_usage table
DROP TRIGGER IF EXISTS trigger_budget_usage_updated_at ON budget_usage;
CREATE TRIGGER trigger_budget_usage_updated_at
    BEFORE UPDATE ON budget_usage
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- ============================================
-- RED LINE EVENTS TABLE (Critical Security)
-- ============================================
CREATE TABLE IF NOT EXISTS red_line_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    red_line VARCHAR(100) NOT NULL,
    attempted_action VARCHAR(255) NOT NULL,
    actor VARCHAR(255),
    mission_id UUID REFERENCES missions(mission_id),
    blocked BOOLEAN DEFAULT TRUE,
    severity VARCHAR(20) DEFAULT 'CRITICAL',
    details JSONB,
    hmac_signature VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_red_line_created_at ON red_line_events(created_at);
CREATE INDEX IF NOT EXISTS idx_red_line_type ON red_line_events(red_line);

-- ============================================
-- MLS OPERATIONS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS mls_operations (
    operation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operation_type VARCHAR(50) NOT NULL,
    source_ring VARCHAR(20) NOT NULL,
    target_ring VARCHAR(20) NOT NULL,
    allowed BOOLEAN NOT NULL,
    actor VARCHAR(255),
    resource VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mls_ops_rings ON mls_operations(source_ring, target_ring);

-- ============================================
-- PERSONA VALIDATION TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS persona_validations (
    validation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    persona_id UUID NOT NULL,
    persona_name VARCHAR(255),
    category VARCHAR(100),
    classification_level VARCHAR(20) NOT NULL,
    signature_valid BOOLEAN,
    attestation_valid BOOLEAN,
    constraints_valid BOOLEAN,
    overall_valid BOOLEAN NOT NULL,
    errors JSONB,
    validated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_persona_valid_at ON persona_validations(validated_at);

-- ============================================
-- SBOM/SLSA VERIFICATION TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS artifact_verifications (
    verification_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    artifact_id UUID NOT NULL,
    artifact_type VARCHAR(50) NOT NULL,
    artifact_name VARCHAR(255) NOT NULL,
    sbom_valid BOOLEAN,
    sbom_format VARCHAR(50),
    provenance_valid BOOLEAN,
    slsa_level INTEGER,
    signature_valid BOOLEAN,
    attestation_valid BOOLEAN,
    license_compliant BOOLEAN,
    prohibited_licenses JSONB,
    overall_valid BOOLEAN NOT NULL,
    verification_hash VARCHAR(128),
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_artifact_ver_at ON artifact_verifications(verified_at);

-- ============================================
-- PROMOTION ATTESTATIONS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS promotion_attestations (
    attestation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    artifact_id UUID NOT NULL,
    from_environment VARCHAR(50) NOT NULL,
    to_environment VARCHAR(50) NOT NULL,
    ring VARCHAR(20) NOT NULL,
    all_gates_passed BOOLEAN NOT NULL,
    security_gate JSONB,
    safety_gate JSONB,
    forensic_gate JSONB,
    impact_gate JSONB,
    performance_gate JSONB,
    ops_gate JSONB,
    fl_ring_gate JSONB,
    approver_id VARCHAR(255),
    approver_signature TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_promotion_att_at ON promotion_attestations(created_at);

-- ============================================
-- HMAC CHAIN TABLE (Tamper Evidence)
-- ============================================
CREATE TABLE IF NOT EXISTS hmac_chain (
    chain_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(mission_id),
    sequence_number BIGINT NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    data_hash VARCHAR(128) NOT NULL,
    previous_hmac VARCHAR(128),
    current_hmac VARCHAR(128) NOT NULL,
    timestamp_rfc3161 TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (mission_id, sequence_number)
);

CREATE INDEX IF NOT EXISTS idx_hmac_mission ON hmac_chain(mission_id);

-- ============================================
-- WORM PROTECTION FOR FORENSIC RECORDS
-- ============================================
-- Prevent modification of forensic records (Write Once Read Many)
CREATE OR REPLACE FUNCTION prevent_forensic_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Forensic records are write-once and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

-- Create triggers if they don't exist
DROP TRIGGER IF EXISTS trigger_forensic_no_update ON forensic_records;
CREATE TRIGGER trigger_forensic_no_update
    BEFORE UPDATE ON forensic_records
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

DROP TRIGGER IF EXISTS trigger_forensic_no_delete ON forensic_records;
CREATE TRIGGER trigger_forensic_no_delete
    BEFORE DELETE ON forensic_records
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

-- ============================================
-- WORM PROTECTION FOR AUDIT LOG
-- ============================================
DROP TRIGGER IF EXISTS trigger_audit_no_update ON audit_log;
CREATE TRIGGER trigger_audit_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

DROP TRIGGER IF EXISTS trigger_audit_no_delete ON audit_log;
CREATE TRIGGER trigger_audit_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

-- ============================================
-- WORM PROTECTION FOR RED LINE EVENTS
-- ============================================
DROP TRIGGER IF EXISTS trigger_red_line_no_update ON red_line_events;
CREATE TRIGGER trigger_red_line_no_update
    BEFORE UPDATE ON red_line_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

DROP TRIGGER IF EXISTS trigger_red_line_no_delete ON red_line_events;
CREATE TRIGGER trigger_red_line_no_delete
    BEFORE DELETE ON red_line_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_forensic_modification();

-- ============================================
-- COMPLIANCE VIEWS
-- ============================================

-- View for gate pass rates
CREATE OR REPLACE VIEW gate_pass_rates AS
SELECT
    gate_name,
    COUNT(*) AS total_validations,
    SUM(CASE WHEN passed THEN 1 ELSE 0 END) AS passed_count,
    ROUND(100.0 * SUM(CASE WHEN passed THEN 1 ELSE 0 END) / COUNT(*), 2) AS pass_rate
FROM gate_results
GROUP BY gate_name;

-- View for red line violations by type
CREATE OR REPLACE VIEW red_line_summary AS
SELECT
    red_line,
    COUNT(*) AS total_attempts,
    SUM(CASE WHEN blocked THEN 1 ELSE 0 END) AS blocked_count,
    MAX(created_at) AS last_attempt
FROM red_line_events
GROUP BY red_line;

-- View for MLS violation attempts
CREATE OR REPLACE VIEW mls_violation_attempts AS
SELECT
    source_ring,
    target_ring,
    operation_type,
    COUNT(*) AS attempts,
    SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END) AS violations
FROM mls_operations
GROUP BY source_ring, target_ring, operation_type;

-- ============================================
-- GRANT PERMISSIONS
-- ============================================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO frostgate;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO frostgate;
