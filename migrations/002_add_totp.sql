-- Add TOTP/2FA support to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE NOT NULL;

-- Create backup codes table for 2FA recovery
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for faster backup code lookups
CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id ON totp_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_backup_codes_code_hash ON totp_backup_codes(code_hash);
