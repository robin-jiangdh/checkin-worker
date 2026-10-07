-- D1 migration: accounts table (API-only port of checkin-panel).
-- Dropped vs the original: promo_state table (promo cards are a desktop UI concern),
-- browser profile bookkeeping (no browser on Workers).

CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  login_method TEXT NOT NULL DEFAULT 'password', -- password | access_token | session
  username TEXT,
  password TEXT,      -- AES-GCM encrypted, base64(iv):base64(ciphertext)
  access_token TEXT,  -- AES-GCM encrypted
  session TEXT,       -- AES-GCM encrypted
  api_user TEXT,      -- not secret: the `new-api-user` id some forks require
  checkin_after TEXT, -- 'HH:MM' daily window, interpreted in CHECKIN_TZ
  avatar_color TEXT,
  avatar_shape TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  last_success INTEGER,
  last_checked_in INTEGER,
  last_quota REAL,
  last_error TEXT,
  failures INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS accounts_identity ON accounts (name, base_url);

-- Probe cache: what each site supports, so the daily sweep does not re-probe
-- every account on every run. 24h TTL, refreshed on manual check-in too.
CREATE TABLE IF NOT EXISTS site_info (
  base_url TEXT PRIMARY KEY,
  info_json TEXT NOT NULL,
  probed_at TEXT NOT NULL
);
