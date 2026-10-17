CREATE TABLE account_imports (
 fingerprint TEXT PRIMARY KEY, user_count INTEGER NOT NULL, identity_count INTEGER NOT NULL,
 revoked_session_count INTEGER NOT NULL, imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Deliberately not granted to the identity runtime role.
