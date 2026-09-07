-- Migration 002: delta-based configuration versioning + change tracking.
-- Apply to existing databases: npx wrangler d1 execute fetch-cf-config-db --remote --file=./migrations/002-delta-versioning.sql -y
-- (Fresh databases can use schema.sql directly.)

ALTER TABLE snapshots ADD COLUMN kind TEXT NOT NULL DEFAULT 'full';      -- 'full' | 'delta'
ALTER TABLE snapshots ADD COLUMN base_version INTEGER;                    -- delta: version this delta applies on top of
ALTER TABLE snapshots ADD COLUMN chain_depth INTEGER NOT NULL DEFAULT 0; -- consecutive deltas above the base full snapshot
ALTER TABLE snapshots ADD COLUMN change_summary TEXT;                     -- JSON: {endpoints, added, changed, item_added, item_removed, item_changed}
ALTER TABLE snapshots ADD COLUMN state_checksum TEXT;                     -- SHA-256 of the full reconstructed state at this version

CREATE TABLE IF NOT EXISTS tracked_zones (
  zone_id            TEXT PRIMARY KEY,
  zone_name          TEXT,
  account_id         TEXT,
  last_version       INTEGER,
  last_checked_at    TEXT,
  last_check_result  TEXT,   -- 'no_change' | 'changed: v<N>' | 'error: <msg>'
  updated_at         TEXT
);
