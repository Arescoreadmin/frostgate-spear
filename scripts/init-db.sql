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

-- Grant permissions (adjust as needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO frostgate;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO frostgate;
