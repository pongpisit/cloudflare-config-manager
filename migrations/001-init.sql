-- Baseline schema (v1): tables for configuration versions, the append-only
-- audit trail and change detection. Fully idempotent (CREATE TABLE IF NOT
-- EXISTS), so `wrangler d1 migrations apply` is safe on a fresh database and
-- on one that already has the tables (e.g. built from schema.sql).
-- Historical note: delta versioning, named snapshots, account scope and the
-- audit-log watermark were incremental migrations; they are squashed into
-- this baseline (schema.sql mirrors it exactly).
-- Configuration versions. The first version for a zone is a full snapshot
-- (kind='full'); subsequent versions usually store only the changed endpoints
-- (kind='delta', payload = endpoint patches + item-level diff detail). A version's
-- full state is reconstructed by walking back to the nearest full snapshot.
CREATE TABLE IF NOT EXISTS snapshots (
  id              TEXT PRIMARY KEY,
  zone_id         TEXT NOT NULL,                       -- zone id, or account id when scope='account'
  zone_name       TEXT NOT NULL,
  account_id      TEXT,
  version         INTEGER NOT NULL,
  kind            TEXT NOT NULL DEFAULT 'full',
  scope           TEXT NOT NULL DEFAULT 'zone',       -- 'zone' | 'account'
  base_version    INTEGER,
  chain_depth     INTEGER NOT NULL DEFAULT 0,
  label           TEXT,
  named           INTEGER NOT NULL DEFAULT 0,                   -- 1 = named snapshot (pinned, exempt from retention)
  trigger_type    TEXT NOT NULL DEFAULT 'manual',   -- manual | scheduled | pre_rollback | rollback
  categories      TEXT NOT NULL DEFAULT '[]',       -- JSON array of category keys
  change_summary  TEXT,                              -- JSON delta summary
  r2_key          TEXT NOT NULL,
  checksum        TEXT NOT NULL,                    -- SHA-256 of the stored payload (full state or delta blob)
  state_checksum  TEXT,                             -- SHA-256 of the full reconstructed state
  size_bytes      INTEGER,
  created_by      TEXT NOT NULL,                    -- actor (Access email / service token / 'scheduled')
  created_at      TEXT NOT NULL,
  deleted_at      TEXT                               -- soft delete only
);

CREATE INDEX IF NOT EXISTS idx_snapshots_zone ON snapshots (zone_id, version DESC);

-- Append-only audit log. Application code only ever INSERTs into this table.
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,        -- snapshot.create | snapshot.view | snapshot.delete | snapshot.diff | rollback.dry_run | rollback.execute | auth.denied
  zone_id     TEXT,
  zone_name   TEXT,
  target_type TEXT,
  target_id   TEXT,
  outcome     TEXT NOT NULL DEFAULT 'success',   -- success | partial | failed | denied
  details     TEXT                              -- JSON
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_zone   ON audit_log (zone_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log (actor, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action, id DESC);

-- Per-zone monotonic snapshot version counter.
CREATE TABLE IF NOT EXISTS zone_seq (
  zone_id      TEXT PRIMARY KEY,
  next_version INTEGER NOT NULL DEFAULT 1
);

-- Zones under change watch (scheduled checks via the CF_API_TOKEN secret).
CREATE TABLE IF NOT EXISTS tracked_zones (
  zone_id            TEXT PRIMARY KEY,
  zone_name          TEXT,
  account_id         TEXT,
  last_version       INTEGER,
  last_checked_at    TEXT,
  last_check_result  TEXT,   -- 'no_change' | 'changed: v<N>' | 'error: <msg>'
  updated_at         TEXT
);

-- How far the account audit log has been consumed (change-triggered checks).
CREATE TABLE IF NOT EXISTS audit_watermarks (
  account_id TEXT PRIMARY KEY,
  last_ts    TEXT NOT NULL
);
