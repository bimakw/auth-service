-- Create audit logs table for tracking authentication events
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    success BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Create enum-like constraint for event types
ALTER TABLE audit_logs ADD CONSTRAINT chk_event_type CHECK (
    event_type IN (
        'login_success',
        'login_failed',
        'logout',
        'register',
        'password_change',
        'password_reset_request',
        'password_reset_complete',
        'totp_enable',
        'totp_disable',
        'totp_verify',
        'oauth_google_login',
        'oauth_github_login',
        'account_locked',
        'token_refresh'
    )
);
