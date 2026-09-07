// ─── Delta-based configuration versioning ────────────────────────────────────
// A version is either:
//   kind='full'  — the complete configuration state (first version, periodic
//                  compaction, or large changes)
//   kind='delta' — only the endpoints that changed since `base_version`,
//                  stored as endpoint patches plus item-level diff detail.
//
// The state at any version is reconstructed by walking the base_version chain
// down to the nearest full snapshot and applying the deltas forward. Every
// version records `state_checksum` (SHA-256 of its full reconstructed state)
// so reconstruction can be verified.

import { deepDiff } from './diff.js';

// Force a full snapshot after this many consecutive deltas.
export const MAX_DELTA_CHAIN = 25;

// Force a full snapshot when the delta blob exceeds this ratio of the base
// version's payload size.
export const DELTA_SIZE_RATIO = 0.5;

// Retention (PAN SCM-style): keep the newest RETENTION_LIMIT non-named versions
// per zone and anything newer than RETENTION_DAYS; older excess versions are
// soft-deleted. Named snapshots and pre_rollback safety nets are never pruned.
// Both values can be overridden with the RETENTION_LIMIT / RETENTION_DAYS vars.
export const RETENTION_LIMIT = 200;
export const RETENTION_DAYS = 180;

// Given a zone's live (non-deleted) version rows, return the ids that should be
// pruned under the retention policy.
export function selectPrunableVersions(versions, { limit = RETENTION_LIMIT, maxAgeDays = RETENTION_DAYS, now = Date.now() } = {}) {
  const countLimit = limit > 0 ? limit : Infinity;
  const nonNamed = versions
    .filter(v => !v.deleted_at && !v.named)
    .sort((a, b) => b.version - a.version);
  const keep = new Set(nonNamed.slice(0, countLimit).map(v => v.id));
  const cutoff = now - maxAgeDays * 86400_000;
  return nonNamed
    .filter(v => !keep.has(v.id) || new Date(v.created_at).getTime() < cutoff)
    .map(v => v.id);
}

// Default name for a named snapshot: config_YYYY-MM-DD-HHMMSS.
export function autoSnapshotName(date = new Date()) {
  return 'config_' + date.toISOString().slice(0, 19).replace(/[T:]/g, '-');
}

// Build a version label attributing a detected change to the Cloudflare audit
// log entries that preceded it: "Auto: by a@x.com, b@y.com — Firewall Rules
// updated, Access policy updated". Entries look like:
//   { when, actor: { email }, action: { type }, resource: { type } }
export function attributionLabel(entries, maxLen = 140) {
  if (!entries || !entries.length) return null;
  const actors = [...new Set(entries.map(e => e?.actor?.email).filter(Boolean))].slice(0, 3);
  const actions = [...new Set(entries.map(e => e?.action?.type).filter(Boolean))].slice(0, 3);
  let label = 'Auto: ';
  if (actors.length) label += 'by ' + actors.join(', ');
  if (actions.length) label += (actors.length ? ' — ' : '') + actions.join(', ');
  if (label === 'Auto: ') label += 'change detected via Cloudflare audit log';
  if (label.length > maxLen) label = label.slice(0, maxLen - 1) + '…';
  return label;
}

// Endpoints whose data is inherently volatile (logs) or retired from the
// catalog (DEX). They never trigger a new version, never enter deltas, and are
// excluded from display diffs and rollback previews — their value from the last
// full snapshot stays in the reconstructed state of old versions.
// NOTE: DEX test definitions were removed from scope; old versions that
// contain them simply stop being compared/fetched going forward.
export const VOLATILE_ENDPOINTS = new Set(['audit_logs', 'dex_tests']);

// Runtime (non-config) keys inside specific endpoints that must not trigger
// versions or appear in diffs — e.g. Cloudflare Tunnel status flaps on
// connector health, Access key rotation state advances daily, DLP match
// counters increment with traffic, Gateway cert binding is runtime state,
// and Access policies carry a derived app linkage count.
export const VOLATILE_KEYS = {
  'tunnels': ['status', 'connections', 'remote_config'],
  'access_keys': ['last_key_rotation_at', 'days_until_next_rotation'],
  'dlp_profiles': ['allowed_match_count'],
  'gateway_certificates': ['binding_status'],
  'access_policies': ['app_count'],
};

const MAX_CHAIN_WALK = 100; // safety guard against corrupted chains/cycles

// ─── Delta computation ──────────────────────────────────────────────────────
// Compare a newly observed state against the recorded base state and produce
// endpoint-level patch ops. Only endpoints that were actually observed in this
// fetch (fetchedOk) are compared — unfetched endpoints keep their recorded
// value instead of being treated as removed.
//
// Returns { ops, detail, summary } where:
//   ops    — [{op:'set', category, endpoint, data}, {op:'meta', meta}] (in order)
//   detail — item-level changes for display (deepDiff output, paths prefixed)
//   summary— {endpoints, added, changed, item_added, item_removed, item_changed}
export function computeEndpointDelta(baseState, newState, fetchedOk) {
  const ops = [];
  const detail = [];
  let added = 0, changed = 0, item_added = 0, item_removed = 0, item_changed = 0;

  const cats = new Set([
    ...Object.keys(newState || {}).filter(k => k !== '_meta'),
    ...Object.keys(baseState || {}).filter(k => k !== '_meta'),
  ]);

  for (const cat of cats) {
    const names = new Set([
      ...Object.keys((newState || {})[cat] || {}),
      ...Object.keys((baseState || {})[cat] || {}),
    ]);
    for (const name of names) {
      if (!fetchedOk.has(`${cat}|${name}`)) continue;      // not observed → keep recorded value
      if (VOLATILE_ENDPOINTS.has(name)) continue;            // volatile → never versions

      const baseVal = baseState?.[cat]?.[name];
      const newVal = newState?.[cat]?.[name];

      if (baseVal === undefined) {
        ops.push({ op: 'set', category: cat, endpoint: name, data: newVal });
        detail.push({ path: `${cat}.${name}`, type: 'added', scope: 'endpoint', after: newVal });
        added++;
        continue;
      }

      const d = deepDiff(baseVal, newVal, { maxChanges: 50, ignoreKeys: VOLATILE_KEYS[name] });
      if (d.changes.length > 0) {
        ops.push({ op: 'set', category: cat, endpoint: name, data: newVal });
        for (const c of d.changes) {
          detail.push({ ...c, path: `${cat}.${name}.${c.path}`, scope: 'item' });
          if (c.type === 'added') item_added++;
          else if (c.type === 'removed') item_removed++;
          else item_changed++;
        }
        changed++;
      }
    }
  }

  return {
    ops,
    detail,
    summary: { endpoints: ops.length, added, changed, item_added, item_removed, item_changed },
  };
}

// Whether the endpoint set changed between two _meta blocks (permissions or
// categories changed) — recorded as a 'meta' op so future checks observe the
// same set.
export function endpointSetChanged(baseMeta, newMeta) {
  const sig = (m) => JSON.stringify(
    ((m && m.fetched_endpoints) || []).map(e => [e.catKey, e.name, e.status]).sort()
  );
  return sig(baseMeta) !== sig(newMeta);
}

// ─── Delta application ──────────────────────────────────────────────────────
// Apply a delta payload to a state, returning a new state (input untouched).
// Ops: 'set' (replace endpoint payload), 'del' (drop endpoint),
//      'meta' (merge _meta — refreshes the tracked endpoint set).
export function applyDelta(state, delta) {
  const s = structuredClone(state);
  for (const op of (delta && delta.ops) || []) {
    if (op.op === 'set') {
      if (!s[op.category] || typeof s[op.category] !== 'object') s[op.category] = {};
      s[op.category][op.endpoint] = structuredClone(op.data);
    } else if (op.op === 'del') {
      if (s[op.category]) delete s[op.category][op.endpoint];
    } else if (op.op === 'meta') {
      s._meta = { ...(s._meta || {}), ...structuredClone(op.meta) };
    }
  }
  return s;
}

// ─── Storage strategy ────────────────────────────────────────────────────────
export function shouldStoreFull({ chainDepth, deltaBytes, baseBytes }) {
  if ((chainDepth ?? 0) >= MAX_DELTA_CHAIN) return true;
  if (baseBytes && deltaBytes && deltaBytes > baseBytes * DELTA_SIZE_RATIO) return true;
  return false;
}

// ─── Reconstruction ─────────────────────────────────────────────────────────
// Reconstruct the full state at `version` for a zone.
//   loadRow(zoneId, versionNumber) → version row (must include kind,
//       base_version, r2_key, checksum) — chain traversal must NOT filter
//       soft-deleted rows (they still carry load-bearing payload data).
//   loadPayload(r2Key, checksum)     → parsed payload (full state or delta blob)
export async function reconstructState(loadRow, loadPayload, zoneId, version) {
  const chain = [];
  const seen = new Set();
  let v = version;
  while (true) {
    if (seen.has(v)) throw new Error(`delta chain cycle detected at version ${v}`);
    seen.add(v);
    if (chain.length > MAX_CHAIN_WALK) throw new Error('delta chain too long — data may be corrupted');

    const row = await loadRow(zoneId, v);
    if (!row) throw new Error(`version ${v} not found for zone while reconstructing state`);

    chain.push(row);
    if (row.kind !== 'delta' || !row.base_version) break; // reached a full snapshot
    v = row.base_version;
  }

  // chain[0] = target version ... chain[last] = full base — apply oldest → newest
  let state = await loadPayload(chain[chain.length - 1].r2_key, chain[chain.length - 1].checksum);
  for (let i = chain.length - 2; i >= 0; i--) {
    const row = chain[i];
    const delta = await loadPayload(row.r2_key, row.checksum);
    state = applyDelta(state, delta);
  }
  return state;
}
