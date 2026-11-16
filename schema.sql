-- DC SH!FTZ database (Cloudflare D1 / SQLite)
-- Every app record is a JSON document: col = record type (staff, requests, ...), id = record id.
-- Test-mode records use the same types with a "t_" prefix (t_staff, t_requests, ...).
CREATE TABLE IF NOT EXISTS docs (
  col        TEXT    NOT NULL,
  id         TEXT    NOT NULL,
  data       TEXT    NOT NULL,
  version    INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,            -- ms since 1970; drives the app's live updates
  deleted    INTEGER NOT NULL DEFAULT 0,  -- kept 30 days so other phones learn about deletions
  PRIMARY KEY (col, id)
);
CREATE INDEX IF NOT EXISTS docs_updated ON docs (updated_at);

-- Login sessions. Only a hash of each token is stored.
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  staff_id   TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_staff ON sessions (staff_id);

-- Wrong-code counter per network address (10 tries per 15 minutes).
CREATE TABLE IF NOT EXISTS login_attempts (
  key          TEXT PRIMARY KEY,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

-- Phones that turned on notifications (one row per phone/browser).
CREATE TABLE IF NOT EXISTS push_subs (
  endpoint   TEXT PRIMARY KEY,
  staff_id   TEXT    NOT NULL,
  p256dh     TEXT    NOT NULL,
  auth       TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS push_subs_staff ON push_subs (staff_id);

-- Server settings it makes for itself (the notification signing key).
CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
