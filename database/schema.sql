-- SQLite schema. All timestamps are unix seconds.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(254) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified_at INTEGER NULL,
    session_version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Email verification and password reset tokens. Only a SHA-256 hash of
-- the token is stored, so a leaked table can't be used to take over accounts.
CREATE TABLE IF NOT EXISTS user_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS user_tokens_user_type ON user_tokens (user_id, type);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    throttle_key CHAR(64) NOT NULL,
    attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS login_attempts_key_time ON login_attempts (throttle_key, attempted_at);
