-- Database initialization script for Prompt Injection Defense Platform
-- Creates necessary tables with proper indexes and constraints

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    rate_limit_per_minute INTEGER DEFAULT 60 NOT NULL,
    rate_limit_per_day INTEGER DEFAULT 10000 NOT NULL
);

-- Usage logs table
CREATE TABLE IF NOT EXISTS usage_logs (
    id BIGSERIAL PRIMARY KEY,
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(50),
    request_size INTEGER,
    response_time_ms INTEGER,
    is_malicious BOOLEAN,
    confidence FLOAT,
    threat_types TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    user_agent VARCHAR(200),
    ip_address VARCHAR(45),
    status_code INTEGER
);

-- Webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL,
    events TEXT[] DEFAULT '{"detection_complete"}' NOT NULL,
    secret_token VARCHAR(64),
    description VARCHAR(200),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    retry_count INTEGER DEFAULT 3 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_triggered_at TIMESTAMP WITH TIME ZONE
);

-- Webhook deliveries table
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    payload TEXT,
    http_status INTEGER,
    response_body TEXT,
    response_time_ms INTEGER,
    attempt_count INTEGER DEFAULT 1 NOT NULL,
    success BOOLEAN,
    error_message TEXT,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    next_retry_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

CREATE INDEX IF NOT EXISTS idx_usage_logs_api_key_id ON usage_logs(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_logs_created_at ON usage_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_endpoint ON usage_logs(endpoint);
CREATE INDEX IF NOT EXISTS idx_usage_logs_is_malicious ON usage_logs(is_malicious);
CREATE INDEX IF NOT EXISTS idx_usage_logs_status_code ON usage_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_usage_logs_api_key_created ON usage_logs(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_created_malicious ON usage_logs(created_at DESC, is_malicious) WHERE is_malicious IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_webhooks_api_key_id ON webhooks(api_key_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(is_active);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event_type ON webhook_deliveries(event_type);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_http_status ON webhook_deliveries(http_status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_success ON webhook_deliveries(success);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry_at ON webhook_deliveries(next_retry_at) WHERE next_retry_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_success ON webhook_deliveries(created_at DESC, success);

-- Insert sample data for testing (optional)
INSERT INTO api_keys (key_hash, name, rate_limit_per_minute, rate_limit_per_day)
VALUES 
    ('sample_hash_for_testing_only', 'Test API Key', 100, 50000)
ON CONFLICT (key_hash) DO NOTHING;

-- Create database user for the application (if not exists)
-- Note: In production, this should be handled separately with proper credentials
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'prompt_defense_user') THEN
        CREATE USER prompt_defense_user WITH PASSWORD 'secure_password_change_in_production';
    END IF;
END
$$;

-- Grant permissions
GRANT CONNECT ON DATABASE prompt_defense TO prompt_defense_user;
GRANT USAGE ON SCHEMA public TO prompt_defense_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO prompt_defense_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO prompt_defense_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO prompt_defense_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO prompt_defense_user;