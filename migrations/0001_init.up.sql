CREATE TABLE users (
  id   INTEGER PRIMARY KEY,
  name TEXT UNIQUE
);
INSERT INTO users (id, name) VALUES (0, NULL); -- the admin

CREATE TABLE sessions (
  token_hash BLOB PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires    INTEGER NOT NULL          -- unix seconds, sliding 30 days
);
CREATE INDEX idx_sessions_expires ON sessions(expires);

CREATE TABLE tokens (
  token_hash BLOB PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('invitation', 'login')),
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires    INTEGER                   -- unix seconds, NULL = never
);
CREATE INDEX idx_tokens_expires ON tokens(expires);
