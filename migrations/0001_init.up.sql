CREATE TABLE users (
  id          INTEGER PRIMARY KEY,
  telegram_id INTEGER UNIQUE,           -- the login credential; NULL for the admin
  name        TEXT,                     -- cosmetic display name
  banned      INTEGER NOT NULL DEFAULT 0
);
INSERT INTO users (id) VALUES (0); -- the admin, claimed via the OIDC login

CREATE TABLE sessions (
  token_hash BLOB PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires    INTEGER NOT NULL          -- unix seconds, sliding 30 days
);
CREATE INDEX idx_sessions_expires ON sessions(expires);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- Registration requests from unknown telegram accounts, waiting for the
-- admin to approve or deny them. One per telegram account; dropped by the
-- cleanup task after an hour.
CREATE TABLE pending_users (
  telegram_id INTEGER PRIMARY KEY,
  name        TEXT,                     -- display name from the telegram profile
  username    TEXT,                     -- @handle from the telegram profile
  created     INTEGER NOT NULL          -- unix seconds
);

-- In-flight admin logins: the browser carries the state token in a cookie,
-- the row holds the matching PKCE verifier, and the SPA path to send the
-- browser back to once the login completed.
CREATE TABLE oidc_logins (
  state_hash BLOB PRIMARY KEY,
  verifier   TEXT NOT NULL,
  return_to  TEXT NOT NULL DEFAULT '/',
  expires    INTEGER NOT NULL          -- unix seconds
);
CREATE INDEX idx_oidc_logins_expires ON oidc_logins(expires);
