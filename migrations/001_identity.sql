CREATE TABLE users (
 id TEXT PRIMARY KEY, email TEXT, email_key TEXT UNIQUE, email_verified SMALLINT NOT NULL DEFAULT 0 CHECK(email_verified IN (0,1)),
 name TEXT NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'user' CHECK(role='user'),
 age_range TEXT CHECK(age_range IS NULL OR age_range IN ('under-18','18-24','25-34','35-44','45-54','55-64','65-plus','prefer-not')),
 gender TEXT CHECK(gender IS NULL OR gender IN ('woman','man','non-binary','self-described','prefer-not')), created_at BIGINT NOT NULL
);
CREATE TABLE identities (
 provider TEXT NOT NULL CHECK(provider IN ('google','facebook')), subject TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(provider,subject), UNIQUE(user_id,provider)
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, created_at BIGINT NOT NULL, auth_at BIGINT NOT NULL, last_seen BIGINT NOT NULL, expires_at BIGINT NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE oauth_states (
 state_hash TEXT PRIMARY KEY, session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
 provider TEXT NOT NULL CHECK(provider IN ('google','facebook')), nonce TEXT NOT NULL, verifier TEXT NOT NULL,
 intent TEXT NOT NULL CHECK(intent IN ('login','link')), user_id TEXT REFERENCES users(id) ON DELETE CASCADE, expires_at BIGINT NOT NULL
);
CREATE TABLE email_tokens (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')), expires_at BIGINT NOT NULL, UNIQUE(user_id,purpose)
);
