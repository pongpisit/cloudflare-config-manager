-- Migration 003: named snapshots + retention support (PAN SCM-style versioning).
-- Apply to existing databases: npx wrangler d1 execute fetch-cf-config-db --remote --file=./migrations/003-named-snapshots.sql -y

ALTER TABLE snapshots ADD COLUMN named INTEGER NOT NULL DEFAULT 0;  -- 1 = named snapshot (pinned, exempt from retention)
