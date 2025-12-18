-- Add GitHub OAuth support
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id VARCHAR(255) UNIQUE;
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
