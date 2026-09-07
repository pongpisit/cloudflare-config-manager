// ─── D1 data access: snapshots metadata + append-only audit log ──────────────

export function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// ── Snapshot versions ───────────────────────────────────────────────────────

// Atomically allocate the next version number for a zone.
export async function nextVersion(env, zoneId) {
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO zone_seq (zone_id, next_version) VALUES (?, 2)
       ON CONFLICT(zone_id) DO UPDATE SET next_version = next_version + 1`
    ).bind(zoneId),
    env.DB.prepare(
      `SELECT next_version - 1 AS v FROM zone_seq WHERE zone_id = ?`
    ).bind(zoneId),
  ]);
  return results[1].results[0].v;
}

const SNAPSHOT_COLS = `id, zone_id, zone_name, account_id, version, kind, scope, base_version, chain_depth,
  label, named, trigger_type, categories, change_summary, r2_key, checksum, state_checksum,
  size_bytes, created_by, created_at, deleted_at`;

export async function insertSnapshot(env, s) {
  await env.DB.prepare(
    `INSERT INTO snapshots
       (id, zone_id, zone_name, account_id, version, kind, scope, base_version, chain_depth, label,
        named, trigger_type, categories, change_summary, r2_key, checksum, state_checksum,
        size_bytes, created_by, created_at, deleted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
  ).bind(
    s.id, s.zone_id, s.zone_name, s.account_id ?? null, s.version, s.kind ?? 'full',
    s.scope ?? 'zone', s.base_version ?? null, s.chain_depth ?? 0, s.label ?? null,
    s.named ? 1 : 0, s.trigger_type,
    JSON.stringify(s.categories || []),
    s.change_summary ? JSON.stringify(s.change_summary) : null,
    s.r2_key, s.checksum, s.state_checksum ?? null,
    s.size_bytes ?? null, s.created_by, s.created_at
  ).run();
}

function rowToMeta(r) {
  if (!r) return null;
  let cats = [];
  try { cats = JSON.parse(r.categories); } catch {}
  let summary = null;
  if (r.change_summary) { try { summary = JSON.parse(r.change_summary); } catch {} }
  return { ...r, categories: cats, change_summary: summary };
}

export async function listSnapshots(env, zoneId, includeDeleted = false) {
  const sql =
    `SELECT ${SNAPSHOT_COLS}
     FROM snapshots WHERE zone_id = ?${includeDeleted ? '' : ' AND deleted_at IS NULL'}
     ORDER BY version DESC`;
  const { results } = await env.DB.prepare(sql).bind(zoneId).all();
  return (results || []).map(rowToMeta);
}

export async function getSnapshot(env, id) {
  const { results } = await env.DB.prepare(
    `SELECT ${SNAPSHOT_COLS} FROM snapshots WHERE id = ?`
  ).bind(id).all();
  return rowToMeta((results || [])[0]);
}

// Latest non-deleted version of a zone.
export async function getLatestVersion(env, zoneId) {
  const { results } = await env.DB.prepare(
    `SELECT ${SNAPSHOT_COLS}
     FROM snapshots WHERE zone_id = ? AND deleted_at IS NULL
     ORDER BY version DESC LIMIT 1`
  ).bind(zoneId).all();
  return rowToMeta((results || [])[0]);
}

// Version row by number — chain traversal, includes soft-deleted rows on
// purpose (their payload data is still load-bearing for later versions).
export async function getVersionByNumber(env, zoneId, version) {
  const { results } = await env.DB.prepare(
    `SELECT ${SNAPSHOT_COLS} FROM snapshots WHERE zone_id = ? AND version = ?`
  ).bind(zoneId, version).all();
  return rowToMeta((results || [])[0]);
}

export async function softDeleteSnapshot(env, id, ts) {
  const res = await env.DB.prepare(
    `UPDATE snapshots SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`
  ).bind(ts, id).run();
  return (res.meta?.changes ?? 0) > 0;
}

// Bulk soft delete (retention pruning). Returns the number of rows deleted.
export async function softDeleteVersions(env, ids, ts) {
  if (!ids || !ids.length) return 0;
  const stmts = ids.map(id =>
    env.DB.prepare(`UPDATE snapshots SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`).bind(ts, id)
  );
  const results = await env.DB.batch(stmts);
  return results.reduce((n, r) => n + (r.meta?.changes ?? 0), 0);
}

// ── Audit log (append-only) ────────────────────────────────────────────────
// NOTE: no update or delete helpers exist on purpose — the audit trail is
// immutable from the application's perspective.

const MAX_DETAILS = 8000;

export async function writeAudit(env, entry) {
  const {
    actor = 'system',
    action,
    zone_id = null,
    zone_name = null,
    target_type = null,
    target_id = null,
    outcome = 'success',
    details = null,
  } = entry;
  let detailsStr = null;
  if (details != null) {
    detailsStr = typeof details === 'string' ? details : JSON.stringify(details);
    if (detailsStr.length > MAX_DETAILS) detailsStr = detailsStr.slice(0, MAX_DETAILS) + '…[truncated]';
  }
  await env.DB.prepare(
    `INSERT INTO audit_log (ts, actor, action, zone_id, zone_name, target_type, target_id, outcome, details)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    new Date().toISOString(), actor, action, zone_id, zone_name,
    target_type, target_id, outcome, detailsStr
  ).run();
}

export async function queryAudit(env, f = {}) {
  const where = [];
  const binds = [];
  if (f.zone_id) { where.push('zone_id = ?'); binds.push(f.zone_id); }
  if (f.actor)  { where.push('actor = ?'); binds.push(f.actor); }
  if (f.action) { where.push('action = ?'); binds.push(f.action); }
  if (f.from)   { where.push('ts >= ?'); binds.push(f.from); }
  if (f.to)     { where.push('ts <= ?'); binds.push(f.to); }
  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const limit = Math.min(Math.max(parseInt(f.limit) || 50, 1), 200);
  const offset = Math.max(parseInt(f.offset) || 0, 0);

  const { results } = await env.DB.prepare(
    `SELECT * FROM audit_log ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`
  ).bind(...binds, limit, offset).all();

  const total = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM audit_log ${whereSql}`
  ).bind(...binds).first();

  return {
    entries: (results || []).map(r => {
      let details = null;
      if (r.details) { try { details = JSON.parse(r.details); } catch { details = r.details; } }
      return { ...r, details };
    }),
    limit,
    offset,
    total: total?.n ?? 0,
  };
}

// ── Tracked zones (scheduled change watch) ─────────────────────────────────

export async function upsertTrackedZone(env, z) {
  await env.DB.prepare(
    `INSERT INTO tracked_zones (zone_id, zone_name, account_id, last_version, last_checked_at, last_check_result, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(zone_id) DO UPDATE SET
       zone_name = excluded.zone_name,
       account_id = excluded.account_id,
       last_version = excluded.last_version,
       last_checked_at = excluded.last_checked_at,
       last_check_result = excluded.last_check_result,
       updated_at = excluded.updated_at`
  ).bind(
    z.zone_id, z.zone_name ?? null, z.account_id ?? null, z.last_version ?? null,
    z.last_checked_at ?? null, z.last_check_result ?? null, new Date().toISOString()
  ).run();
}

export async function listTrackedZones(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM tracked_zones ORDER BY zone_name`
  ).all();
  return results || [];
}

// Overview rows for the targets dashboard: tracked zones joined with their
// version counts, scope and latest version number.
export async function listTrackedZoneOverview(env) {
  const { results } = await env.DB.prepare(
    `SELECT t.zone_id, t.zone_name, t.account_id, t.last_version,
            t.last_checked_at, t.last_check_result,
            (SELECT COUNT(*) FROM snapshots s
              WHERE s.zone_id = t.zone_id AND s.deleted_at IS NULL) AS version_count,
            (SELECT scope FROM snapshots s
              WHERE s.zone_id = t.zone_id AND s.deleted_at IS NULL
              ORDER BY version DESC LIMIT 1) AS scope
     FROM tracked_zones t
     ORDER BY t.zone_name`
  ).all();
  return results || [];
}

export async function recordTrackedZoneCheck(env, zoneId, result, version) {
  await env.DB.prepare(
    `UPDATE tracked_zones
     SET last_checked_at = ?, last_check_result = ?, last_version = COALESCE(?, last_version), updated_at = ?
     WHERE zone_id = ?`
  ).bind(new Date().toISOString(), String(result).slice(0, 300), version ?? null, new Date().toISOString(), zoneId).run();
}

// ── Audit-log watermark (change-triggered scheduled checks) ────────────────

export async function getAuditWatermark(env, accountId) {
  const row = await env.DB.prepare(
    `SELECT last_ts FROM audit_watermarks WHERE account_id = ?`
  ).bind(accountId).first();
  return row?.last_ts ?? null;
}

export async function setAuditWatermark(env, accountId, ts) {
  await env.DB.prepare(
    `INSERT INTO audit_watermarks (account_id, last_ts) VALUES (?, ?)
     ON CONFLICT(account_id) DO UPDATE SET last_ts = excluded.last_ts`
  ).bind(accountId, ts).run();
}
