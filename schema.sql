-- Logger Service Database Schema
-- This file sets up the required tables and indexes for the D1 database

-- Logs table for persistent storage
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    service TEXT,
    domain TEXT,
    user_id TEXT,
    session_id TEXT,
    request_id TEXT,
    metadata TEXT, -- JSON string
    context TEXT, -- JSON string  
    stack_trace TEXT,
    category TEXT,
    priority INTEGER DEFAULT 3,
    processed BOOLEAN DEFAULT FALSE,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_service ON logs(service);
CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(domain);
CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id);
CREATE INDEX IF NOT EXISTS idx_logs_request_id ON logs(request_id);
CREATE INDEX IF NOT EXISTS idx_logs_category ON logs(category);
CREATE INDEX IF NOT EXISTS idx_logs_priority ON logs(priority);
CREATE INDEX IF NOT EXISTS idx_logs_processed ON logs(processed);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_logs_service_level ON logs(service, level);
CREATE INDEX IF NOT EXISTS idx_logs_domain_timestamp ON logs(domain, timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_level_timestamp ON logs(level, timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_service_timestamp ON logs(service, timestamp);

-- Log patterns table for pattern recognition
CREATE TABLE IF NOT EXISTS log_patterns (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    pattern_type TEXT NOT NULL, -- error, warning, info, etc.
    frequency INTEGER DEFAULT 1,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    services TEXT, -- JSON array of services where this pattern occurs
    domains TEXT, -- JSON array of domains
    severity TEXT DEFAULT 'medium',
    auto_created BOOLEAN DEFAULT TRUE,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for pattern matching
CREATE INDEX IF NOT EXISTS idx_patterns_type ON log_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_patterns_frequency ON log_patterns(frequency);
CREATE INDEX IF NOT EXISTS idx_patterns_severity ON log_patterns(severity);
CREATE INDEX IF NOT EXISTS idx_patterns_last_seen ON log_patterns(last_seen);

-- Analytics aggregations table
CREATE TABLE IF NOT EXISTS log_analytics (
    id TEXT PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    dimensions TEXT, -- JSON object with dimension key-value pairs
    timestamp INTEGER NOT NULL,
    period TEXT NOT NULL, -- hour, day, week, month
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Analytics indexes
CREATE INDEX IF NOT EXISTS idx_analytics_metric ON log_analytics(metric_name);
CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON log_analytics(timestamp);
CREATE INDEX IF NOT EXISTS idx_analytics_period ON log_analytics(period);
CREATE INDEX IF NOT EXISTS idx_analytics_metric_period ON log_analytics(metric_name, period);

-- Log processing queue for background tasks
CREATE TABLE IF NOT EXISTS processing_queue (
    id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL, -- triaging, pattern_analysis, alert, etc.
    payload TEXT NOT NULL, -- JSON payload
    priority INTEGER DEFAULT 5,
    status TEXT DEFAULT 'pending', -- pending, processing, completed, failed
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    scheduled_for INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    error_message TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Queue indexes
CREATE INDEX IF NOT EXISTS idx_queue_status ON processing_queue(status);
CREATE INDEX IF NOT EXISTS idx_queue_priority ON processing_queue(priority);
CREATE INDEX IF NOT EXISTS idx_queue_scheduled ON processing_queue(scheduled_for);
CREATE INDEX IF NOT EXISTS idx_queue_task_type ON processing_queue(task_type);
CREATE INDEX IF NOT EXISTS idx_queue_status_priority ON processing_queue(status, priority);

-- API keys table for authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    permissions TEXT, -- JSON array of permissions
    domains TEXT, -- JSON array of allowed domains
    rate_limit INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at INTEGER,
    last_used INTEGER,
    usage_count INTEGER DEFAULT 0,
    created_by TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- API keys indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at);

-- System metrics for monitoring
CREATE TABLE IF NOT EXISTS system_metrics (
    id TEXT PRIMARY KEY,
    metric_type TEXT NOT NULL, -- cpu, memory, requests, errors, etc.
    value REAL NOT NULL,
    tags TEXT, -- JSON object with tags
    timestamp INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- System metrics indexes
CREATE INDEX IF NOT EXISTS idx_metrics_type ON system_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_type_timestamp ON system_metrics(metric_type, timestamp);

-- Alerts configuration
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    condition_type TEXT NOT NULL, -- threshold, pattern, anomaly
    condition_config TEXT NOT NULL, -- JSON configuration
    is_active BOOLEAN DEFAULT TRUE,
    notification_config TEXT, -- JSON with webhooks, emails, etc.
    last_triggered INTEGER,
    trigger_count INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Alerts indexes
CREATE INDEX IF NOT EXISTS idx_alerts_active ON alerts(is_active);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(condition_type);

-- Update triggers to maintain updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_logs_timestamp 
    AFTER UPDATE ON logs
BEGIN
    UPDATE logs SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_patterns_timestamp 
    AFTER UPDATE ON log_patterns
BEGIN
    UPDATE log_patterns SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_queue_timestamp 
    AFTER UPDATE ON processing_queue
BEGIN
    UPDATE processing_queue SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_api_keys_timestamp 
    AFTER UPDATE ON api_keys
BEGIN
    UPDATE api_keys SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_alerts_timestamp 
    AFTER UPDATE ON alerts
BEGIN
    UPDATE alerts SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- Insert initial data
INSERT OR IGNORE INTO log_patterns (id, pattern, pattern_type, frequency, first_seen, last_seen, severity) VALUES
('error-500', 'Internal Server Error', 'error', 0, strftime('%s', 'now'), strftime('%s', 'now'), 'high'),
('error-404', 'Not Found', 'error', 0, strftime('%s', 'now'), strftime('%s', 'now'), 'medium'),
('error-auth', 'Authentication Failed', 'error', 0, strftime('%s', 'now'), strftime('%s', 'now'), 'high'),
('warn-rate-limit', 'Rate limit exceeded', 'warning', 0, strftime('%s', 'now'), strftime('%s', 'now'), 'medium');

-- Schema version for migrations
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER DEFAULT (strftime('%s', 'now'))
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);