-- Migration 004: account-scoped versioning (Cloudflare One is account-level,
-- not zone-level). Existing rows keep scope 'zone'; account-scoped versions
-- store the account id in zone_id with scope='account'.
ALTER TABLE snapshots ADD COLUMN scope TEXT NOT NULL DEFAULT 'zone';  -- 'zone' | 'account'
