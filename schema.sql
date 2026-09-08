-- OSINT CTF — D1 schema
-- Apply: wrangler d1 execute osint_ctf --file=./schema.sql --remote

CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS challenges (
  id           TEXT PRIMARY KEY,
  category     TEXT NOT NULL,
  title        TEXT NOT NULL,
  prompt       TEXT NOT NULL,
  initial      INTEGER NOT NULL DEFAULT 100,
  minimum      INTEGER NOT NULL DEFAULT 50,
  decay        INTEGER NOT NULL DEFAULT 20,   -- solves at which value approaches minimum
  attempts_max INTEGER NOT NULL DEFAULT 10,
  holdoff_ms   INTEGER NOT NULL DEFAULT 30000,
  hint         TEXT,                          -- optional; empty/NULL = no hint
  hint_cost    INTEGER NOT NULL DEFAULT 0,
  answers      TEXT NOT NULL DEFAULT '',      -- accepted answers, one per line (plaintext, admin-editable)
  solution     TEXT,                          -- revealed only after event end
  sort         INTEGER NOT NULL DEFAULT 0,
  active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS users (
  uuid       TEXT PRIMARY KEY,   -- client-generated, the real identity
  name       TEXT NOT NULL,      -- mutable display label
  name_lc    TEXT NOT NULL UNIQUE,
  created_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS solves (
  uuid         TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  ts_ms        INTEGER NOT NULL,
  scored       INTEGER NOT NULL DEFAULT 1,  -- 0 = solved after event end (practice, no points)
  PRIMARY KEY (uuid, challenge_id)
);
CREATE INDEX IF NOT EXISTS idx_solves_ch ON solves(challenge_id, scored);

CREATE TABLE IF NOT EXISTS attempts (
  uuid         TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  last_ms      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (uuid, challenge_id)
);

CREATE TABLE IF NOT EXISTS hint_unlocks (
  uuid         TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  PRIMARY KEY (uuid, challenge_id)
);
