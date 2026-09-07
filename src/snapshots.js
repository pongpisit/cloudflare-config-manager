// ─── Version (snapshot/delta), rollback and audit API handlers ───────────────

import {
  nextVersion, insertSnapshot, listSnapshots, getSnapshot, getLatestVersion,
  getVersionByNumber, softDeleteSnapshot, softDeleteVersions, writeAudit, queryAudit,
  httpError, upsertTrackedZone, recordTrackedZoneCheck, listTrackedZoneOverview,
} from './db.js';
import { putSnapshotPayload, getSnapshotPayload, objectChecksum } from './store.js';
import { fetchEndpoints, normalizeToken } from './cfapi.js';
import { diffConfigs } from './diff.js';
import { runRollback } from './rollback.js';
import {
  computeEndpointDelta, endpointSetChanged, applyDelta, shouldStoreFull, reconstructState,
  selectPrunableVersions, autoSnapshotName, RETENTION_LIMIT, RETENTION_DAYS, VOLATILE_ENDPOINTS,
  VOLATILE_KEYS,
} from './versioning.js';

export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

// ─── State loading (transparent full/delta reconstruction) ──────────────────
// Resolves any version row to its full configuration state. Full versions are
// read straight from R2; delta versions are reconstructed by walking the
// base_version chain and verified against state_checksum.
export async function loadVersionState(env, row) {
  if (row.kind !== 'delta') {
    return getSnapshotPayload(env, row.r2_key, row.checksum);
  }
  const state = await reconstructState(
    (zoneId, version) => getVersionByNumber(env, zoneId, version),
    (r2Key, checksum) => getSnapshotPayload(env, r2Key, checksum),
    row.zone_id,
    row.version
  );
  if (row.state_checksum) {
    const checksum = await objectChecksum(state);
    if (checksum !== row.state_checksum) {
      throw httpError(500, `Integrity check failed: reconstructed state of v${row.version} does not match its recorded checksum`);
    }
  }
  return state;
}

// ─── Retention pruning (PAN SCM-style) ──────────────────────────────────────
// Keeps the newest RETENTION_LIMIT non-named versions and anything newer than
// RETENTION_DAYS; prunes the rest (soft delete — payloads stay for chain
// integrity and the audit trail records the prune). Named snapshots are pinned.
async function pruneVersions(env, zoneId) {
  const limit = parseInt(env.RETENTION_LIMIT ?? '', 10);
  const days = parseInt(env.RETENTION_DAYS ?? '', 10);
  const versions = await listSnapshots(env, zoneId, false);
  const prunable = selectPrunableVersions(versions, {
    limit: Number.isFinite(limit) ? limit : undefined,
    maxAgeDays: Number.isFinite(days) ? days : undefined,
  });
  if (!prunable.length) return 0;
  const n = await softDeleteVersions(env, prunable, new Date().toISOString());
  if (n > 0) {
    await writeAudit(env, {
      actor: 'system', action: 'retention.prune', zone_id: zoneId, outcome: 'success',
      details: {
        pruned: n,
        limit: Number.isFinite(limit) ? limit : RETENTION_LIMIT,
        max_age_days: Number.isFinite(days) ? days : RETENTION_DAYS,
        note: 'soft-deleted; payloads retained for delta chain integrity',
      },
    });
  }
  return n;
}

// ─── Version creation (delta-aware) ─────────────────────────────────────────
// Records `state` as a new version for its zone.
//   name (string/true) → named snapshot: always stored FULL and pinned
//   (exempt from retention) — a known-good configuration you can return to.
//   previewOnly → compute drift vs the latest version WITHOUT saving:
//   returns {would_create: true, change_summary} instead of inserting.
// If the zone has a previous version and the observed configuration did not
// change, NO new version is created ({created: false, no_change: true}).
// Otherwise a delta version is stored (unless the delta is large / chain deep).
export async function createVersion(env, { state, label, triggerType, actor, zoneName, name, previewOnly }) {
  // Versioning scope: 'zone' (zone-level config) or 'account' (Cloudflare One
  // and other account-level configuration — the account id is the version key).
  const scope = state?._meta?.scope === 'account' ? 'account' : 'zone';
  const scopeId = scope === 'account' ? state?._meta?.account_id : state?._meta?.zone_id;
  if (!state || typeof state !== 'object' || !state._meta || !scopeId) {
    throw httpError(400, 'Invalid payload: missing _meta.' + (scope === 'account' ? 'account_id' : 'zone_id'));
  }
  if (!['manual', 'pre_rollback', 'scheduled', 'rollback'].includes(triggerType)) {
    throw httpError(400, 'Invalid trigger_type');
  }

  // Named snapshot resolution
  let namedName = null;
  if (name === true) namedName = autoSnapshotName();
  else if (typeof name === 'string' && name.trim()) namedName = name.trim().slice(0, 64);
  const isNamed = namedName !== null;

  const zoneId = scopeId; // version key: zone id or account id
  const zoneNameR = zoneName || state._meta.zone_name || (scope === 'account' ? 'Account — Cloudflare One' : scopeId);
  const fetchedOk = new Set(
    (state._meta.fetched_endpoints || [])
      .filter(e => e.status === 'ok')
      .map(e => `${e.catKey}|${e.name}`)
  );

  const latest = await getLatestVersion(env, zoneId);

  // First version for this zone → always a full snapshot.
  // Named snapshots are always stored FULL (self-contained, pinned).
  if (!latest || isNamed) {
    const version = await nextVersion(env, zoneId);
    const id = crypto.randomUUID();
    const r2Key = `versions/${zoneId}/${String(version).padStart(5, '0')}-${id}.json`;
    const { checksum, size } = await putSnapshotPayload(env, r2Key, state);
    const now = new Date().toISOString();
    const row = {
      id, zone_id: zoneId, zone_name: zoneNameR, account_id: state._meta.account_id ?? null,
      version, kind: 'full', scope, base_version: null, chain_depth: 0,
      label: isNamed ? namedName : (label ?? null),
      named: isNamed ? 1 : 0,
      trigger_type: triggerType,
      categories: state._meta.categories_requested || [],
      change_summary: { endpoints: fetchedOk.size, added: fetchedOk.size, changed: 0, item_added: 0, item_removed: 0, item_changed: 0 },
      r2_key: r2Key, checksum, state_checksum: checksum, size_bytes: size,
      created_by: actor, created_at: now,
    };
    await insertSnapshot(env, row);
    await writeAudit(env, {
      actor, action: 'snapshot.create', zone_id: zoneId, zone_name: zoneNameR,
      target_type: 'snapshot', target_id: id,
      details: {
        version, kind: 'full', named: isNamed, name: isNamed ? namedName : undefined,
        trigger_type: triggerType, label, size_bytes: size, endpoints: fetchedOk.size, checksum,
      },
    });
    await upsertTrackedZone(env, {
      zone_id: zoneId, zone_name: zoneNameR, account_id: state._meta.account_id ?? null,
      last_version: version, last_checked_at: now,
      last_check_result: isNamed ? 'named snapshot saved' : 'initial version',
    });
    await pruneVersions(env, zoneId);
    const { r2_key, ...pub } = row;
    return { created: true, ...pub };
  }

  // Delta against the latest recorded state.
  const baseState = await loadVersionState(env, latest);
  const delta = computeEndpointDelta(baseState, state, fetchedOk);

  if (delta.ops.length === 0) {
    // No configuration change → no new version.
    await recordTrackedZoneCheck(env, zoneId, 'no_change', latest.version);
    return { created: false, no_change: true, version: latest.version, id: latest.id };
  }

  // Drift preview: report what would be recorded without writing anything.
  if (previewOnly) {
    return { created: false, no_change: false, would_create: true, version: latest.version, change_summary: delta.summary };
  }

  // Keep the tracked endpoint set in sync (permissions/categories may have
  // changed) — rides along only with real versions, never triggers one.
  const deltaPayload = { ops: delta.ops, detail: delta.detail, from_version: latest.version };
  if (endpointSetChanged(baseState._meta, state._meta)) {
    deltaPayload.ops = [
      ...delta.ops,
      {
        op: 'meta',
        meta: {
          zone_id: zoneId, zone_name: zoneNameR, account_id: state._meta.account_id ?? null,
          categories_requested: state._meta.categories_requested || [],
          fetched_endpoints: state._meta.fetched_endpoints,
        },
      },
    ];
  }

  const chainDepth = (latest.chain_depth ?? 0) + 1;
  const deltaBytes = JSON.stringify(deltaPayload).length;
  const full = shouldStoreFull({ chainDepth, deltaBytes, baseBytes: latest.size_bytes });

  const version = await nextVersion(env, zoneId);
  const id = crypto.randomUUID();
  const r2Key = `versions/${zoneId}/${String(version).padStart(5, '0')}-${id}.json`;
  const now = new Date().toISOString();

  let kind, r2Payload, checksum, size, stateChecksum;
  if (full) {
    kind = 'full';
    r2Payload = state;
    const stored = await putSnapshotPayload(env, r2Key, state);
    checksum = stored.checksum;
    size = stored.size;
    stateChecksum = stored.checksum;
  } else {
    kind = 'delta';
    r2Payload = deltaPayload;
    const stored = await putSnapshotPayload(env, r2Key, deltaPayload);
    checksum = stored.checksum;
    size = stored.size;
    stateChecksum = await objectChecksum(applyDelta(baseState, deltaPayload));
  }

  const row = {
    id, zone_id: zoneId, zone_name: zoneNameR, account_id: state._meta.account_id ?? null,
    version, kind, scope, base_version: latest.version, chain_depth: full ? 0 : chainDepth,
    label: label ?? null,
    named: 0,
    trigger_type: triggerType,
    categories: state._meta.categories_requested || latest.categories,
    change_summary: delta.summary,
    r2_key: r2Key, checksum, state_checksum: stateChecksum, size_bytes: size,
    created_by: actor, created_at: now,
  };
  await insertSnapshot(env, row);
  await writeAudit(env, {
    actor, action: 'snapshot.create', zone_id: zoneId, zone_name: zoneNameR,
    target_type: 'snapshot', target_id: id,
    details: {
      version, kind, trigger_type: triggerType, label, size_bytes: size,
      change_summary: delta.summary, base_version: latest.version, checksum, state_checksum: stateChecksum,
    },
  });
  await upsertTrackedZone(env, {
    zone_id: zoneId, zone_name: zoneNameR, account_id: row.account_id,
    last_version: version, last_checked_at: now,
    last_check_result: `changed: v${version} (${delta.summary.endpoints} endpoint(s))`,
  });
  await pruneVersions(env, zoneId);
  const { r2_key, ...pub } = row;
  return { created: true, change_summary: delta.summary, ...pub };
}

// ─── Change detection ───────────────────────────────────────────────────────
// Fetch the live configuration using the tracked endpoint set and record a new
// delta version if anything changed. Shared by the on-demand API check and the
// scheduled cron. `token` must be a normalized Bearer token.
export async function checkAndVersionZone(env, { token, zoneId, trigger, actor, label, previewOnly }) {
  const latest = await getLatestVersion(env, zoneId);
  if (!latest) throw httpError(404, 'No version exists for this zone yet — save one first');

  const state = await loadVersionState(env, latest);
  const live = await fetchLiveFromSnapshot(token, state, null);
  const okCount = live.statuses.filter(s => s.status === 'ok').length;
  if (!okCount) {
    await recordTrackedZoneCheck(env, zoneId, 'error: no endpoints could be fetched', latest.version);
    throw httpError(400, 'Live configuration could not be fetched — check token permissions');
  }

  const newState = {
    ...live.data,
    _meta: {
      ...state._meta,
      timestamp: new Date().toISOString(),
      zone_name: latest.zone_name,
      total_fetched: okCount,
      total_skipped: live.statuses.length - okCount,
      fetched_endpoints: live.statuses,
    },
  };

  const result = await createVersion(env, {
    state: newState,
    triggerType: trigger,
    actor,
    label: label ?? (trigger === 'scheduled' ? null : 'Change detected via check'),
    zoneName: latest.zone_name,
    previewOnly,
  });

  if (result.created) {
    await recordTrackedZoneCheck(env, zoneId, `changed: v${result.version}`, result.version);
  }
  return result;
}

// ─── Fetch live state using a version's endpoint list ───────────────────────

export async function fetchLiveFromSnapshot(token, payload, cats) {
  const catSet = cats ? new Set(cats) : null;
  const eps = (payload._meta?.fetched_endpoints || [])
    .filter(e => e.status === 'ok' && (!catSet || catSet.has(e.catKey)))
    .filter(e => !VOLATILE_ENDPOINTS.has(e.name)); // skip volatile/retired endpoints (logs, DEX)
  const results = await fetchEndpoints(token, eps.map(e => ({ catKey: e.catKey, name: e.name, path: e.path })));
  const data = {};
  const statuses = [];
  for (const r of results) {
    statuses.push({ catKey: r.catKey, name: r.name, path: r.path, status: r.status, http: r.http });
    if (r.status === 'ok') {
      if (!data[r.catKey]) data[r.catKey] = {};
      data[r.catKey][r.name] = r.data;
    }
  }
  return { data, statuses };
}

// ─── Route handlers ────────────────────────────────────────────────────────

export async function handleSnapshotCreate(env, request, actor) {
  const body = await request.json().catch(() => null);
  if (!body?.payload) throw httpError(400, 'Missing "payload" (the fetched configuration object)');
  const result = await createVersion(env, {
    state: body.payload,
    zoneName: body.zone_name,
    label: body.label,
    // body.name (string/true) → named snapshot (pinned, always full)
    name: body.name,
    triggerType: 'manual',
    actor: actor.actor,
  });
  const { r2_key, ...pub } = result;
  return jsonResponse(pub);
}

export async function handleVersionCheck(env, request, actor) {
  const body = await request.json().catch(() => null);
  const zoneId = body?.zone_id;
  if (!zoneId) throw httpError(400, 'zone_id required');
  const token = normalizeToken(request.headers.get('Authorization'));
  if (!token) throw httpError(400, 'Authorization header (Cloudflare API token) required');
  // preview: true → compute drift vs the latest version WITHOUT saving
  // (used by the post-fetch drift banner).
  const result = await checkAndVersionZone(env, {
    token, zoneId, trigger: 'manual', actor: actor.actor, label: null,
    previewOnly: !!body?.preview,
  });
  return jsonResponse({ zone_id: zoneId, ...result });
}

// Overview rows for the targets dashboard.
export async function handleTrackedZones(env) {
  return jsonResponse({ tracked: await listTrackedZoneOverview(env) });
}

export async function handleSnapshotList(env, url) {
  const zoneId = url.searchParams.get('zone_id');
  if (!zoneId) throw httpError(400, 'zone_id query parameter required');
  const includeDeleted = url.searchParams.get('include_deleted') === 'true';
  const snaps = await listSnapshots(env, zoneId, includeDeleted);
  return jsonResponse({ snapshots: snaps.map(({ r2_key, ...s }) => s) });
}

export async function handleSnapshotGet(env, actor, id) {
  const meta = await getSnapshot(env, id);
  if (!meta || meta.deleted_at) throw httpError(404, 'Snapshot not found');
  const payload = await loadVersionState(env, meta);
  await writeAudit(env, {
    actor: actor.actor, action: 'snapshot.view', zone_id: meta.zone_id,
    zone_name: meta.zone_name, target_type: 'snapshot', target_id: id,
    details: { version: meta.version, kind: meta.kind },
  });
  // Present the version's own metadata rather than the base snapshot's.
  payload._meta = {
    ...payload._meta,
    timestamp: meta.created_at,
    zone_name: meta.zone_name,
    version: meta.version,
    kind: meta.kind,
  };
  return new Response(JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

// The recorded change detail of a single version (what changed vs its base).
export async function handleVersionChanges(env, actor, id) {
  const meta = await getSnapshot(env, id);
  if (!meta || meta.deleted_at) throw httpError(404, 'Snapshot not found');
  await writeAudit(env, {
    actor: actor.actor, action: 'snapshot.view', zone_id: meta.zone_id,
    zone_name: meta.zone_name, target_type: 'snapshot', target_id: id,
    details: { version: meta.version, view: 'changes' },
  });
  if (meta.kind !== 'delta') {
    return jsonResponse({
      version: meta.version, kind: 'full', from_version: null, changes: [],
      summary: meta.change_summary || null,
      note: 'Full snapshot — complete state recorded, no delta to display',
    });
  }
  const delta = await getSnapshotPayload(env, meta.r2_key, meta.checksum);
  return jsonResponse({
    version: meta.version,
    kind: 'delta',
    from_version: delta.from_version,
    changes: delta.detail || [],
    summary: meta.change_summary || null,
  });
}

export async function handleSnapshotDelete(env, url, actor, id) {
  const meta = await getSnapshot(env, id);
  if (!meta) throw httpError(404, 'Snapshot not found');
  if (meta.deleted_at) throw httpError(404, 'Snapshot already deleted');
  const force = url.searchParams.get('force') === 'true';
  if (meta.trigger_type === 'pre_rollback' && !force) {
    throw httpError(409, 'pre_rollback snapshots are safety nets (state before a rollback). Pass ?force=true to delete anyway.');
  }
  await softDeleteSnapshot(env, id, new Date().toISOString());
  await writeAudit(env, {
    actor: actor.actor, action: 'snapshot.delete', zone_id: meta.zone_id,
    zone_name: meta.zone_name, target_type: 'snapshot', target_id: id,
    details: { version: meta.version, kind: meta.kind, trigger_type: meta.trigger_type, forced: force },
  });
  return jsonResponse({ deleted: true });
}

export async function handleSnapshotDiff(env, request, actor, id, url) {
  const vs = url.searchParams.get('vs') || 'live';
  const meta = await getSnapshot(env, id);
  if (!meta || meta.deleted_at) throw httpError(404, 'Snapshot not found');
  const payload = await loadVersionState(env, meta);

  let targetData, targetLabel, unavailable = [];
  if (vs === 'live') {
    const token = normalizeToken(request.headers.get('Authorization'));
    if (!token) throw httpError(400, 'Diff vs live requires the Authorization header (Cloudflare API token)');
    const live = await fetchLiveFromSnapshot(token, payload, null);
    targetData = live.data;
    targetLabel = 'live configuration';
    unavailable = live.statuses
      .filter(s => s.status !== 'ok')
      .map(s => ({ category: s.catKey, endpoint: s.name, reason: s.status }));
  } else {
    const other = await getSnapshot(env, vs);
    if (!other || other.deleted_at) throw httpError(404, 'Comparison snapshot not found');
    targetData = await loadVersionState(env, other);
    targetLabel = `v${other.version} (${other.created_at})`;
  }

  const skip = new Set(unavailable.map(u => `${u.category}|${u.endpoint}`));
  // Volatile endpoints (runtime data) are excluded from display diffs, and
  // per-endpoint volatile keys (e.g. tunnel runtime status) are ignored.
  for (const e of (payload._meta?.fetched_endpoints || [])) {
    if (VOLATILE_ENDPOINTS.has(e.name)) skip.add(`${e.catKey}|${e.name}`);
  }
  const diff = diffConfigs(payload, targetData, { skip, volatileKeys: VOLATILE_KEYS });

  await writeAudit(env, {
    actor: actor.actor, action: 'snapshot.diff', zone_id: meta.zone_id,
    zone_name: meta.zone_name, target_type: 'snapshot', target_id: id,
    details: { vs: targetLabel, ...diff.summary, unavailable_endpoints: unavailable.length },
  });

  return jsonResponse({
    snapshot: { id: meta.id, version: meta.version, zone_name: meta.zone_name, created_at: meta.created_at },
    vs: targetLabel,
    summary: diff.summary,
    truncated: diff.truncated,
    changes: diff.changes,
    skipped: unavailable,
  });
}

export async function handleRollback(env, request, actor) {
  const body = await request.json().catch(() => null);
  const snapshotId = body?.snapshot_id;
  const dryRun = !!body?.dry_run;
  const token = normalizeToken(request.headers.get('Authorization'));

  try {
    if (!snapshotId) throw httpError(400, 'snapshot_id required');
    if (!token) throw httpError(400, 'Authorization header (Cloudflare API token with Edit permissions) required');

    const meta = await getSnapshot(env, snapshotId);
    if (!meta || meta.deleted_at) throw httpError(404, 'Snapshot not found');
    const targetState = await loadVersionState(env, meta);

    const requested = Array.isArray(body.categories) ? body.categories.filter(c => meta.categories.includes(c)) : [];
    const cats = requested.length ? requested : meta.categories;
    if (!cats.length) throw httpError(400, 'Snapshot has no categories to roll back');

    // Fetch the current live state for the same endpoint set
    const live = await fetchLiveFromSnapshot(token, targetState, cats);
    if (!live.statuses.some(s => s.status === 'ok')) {
      throw httpError(400, 'Live configuration could not be fetched for any endpoint — check that the API token has the required permissions');
    }

    // Safety net: record the current live state as a version so the rollback
    // itself can be undone. If nothing drifted since the latest version, no new
    // version is needed — the existing latest version IS the pre-rollback state.
    let preSnapshot = null;
    if (!dryRun) {
      const okCount = live.statuses.filter(s => s.status === 'ok').length;
      const livePayload = {
        ...live.data,
        _meta: {
          ...targetState._meta,
          timestamp: new Date().toISOString(),
          zone_id: meta.zone_id,
          zone_name: meta.zone_name,
          account_id: targetState._meta?.account_id ?? null,
          categories_requested: cats,
          total_fetched: okCount,
          total_skipped: live.statuses.length - okCount,
          fetched_endpoints: live.statuses,
        },
      };
      const pre = await createVersion(env, {
        state: livePayload,
        zoneName: meta.zone_name,
        label: `Auto: state before rollback to v${meta.version}`,
        triggerType: 'pre_rollback',
        actor: actor.actor,
      });
      preSnapshot = { id: pre.id, version: pre.version, no_change: !!pre.no_change };
    }

    const report = await runRollback({ token, payload: targetState, categories: cats, dryRun, live });

    // Pre-commit diff: what the rollback will change (live → target version).
    // Volatile endpoints (rolling logs) are excluded — they always "differ"
    // but can never be restored.
    const skip = new Set(live.statuses.filter(s => s.status !== 'ok').map(s => `${s.catKey}|${s.name}`));
    for (const e of (targetState._meta?.fetched_endpoints || [])) {
      if (VOLATILE_ENDPOINTS.has(e.name)) skip.add(`${e.catKey}|${e.name}`);
    }
    const stateDiff = diffConfigs(live.data, targetState, { skip });

    // PAN SCM semantics: a restore bumps the version number — record the
    // restored live state as a new version so the history reflects the restore.
    let postRestoreVersion = null;
    let postRestoreError = null;
    if (!dryRun && report.totals.ops_ok > 0) {
      try {
        const pr = await checkAndVersionZone(env, {
          token, zoneId: meta.zone_id, trigger: 'rollback', actor: actor.actor,
          label: `Restored from v${meta.version}`,
        });
        postRestoreVersion = pr.created ? { version: pr.version } : null;
      } catch (e) {
        postRestoreError = String(e?.message || e);
      }
    }

    const outcome = (report.totals.ops_failed > 0 || report.totals.error > 0)
      ? (report.totals.ops_ok > 0 ? 'partial' : 'failed')
      : 'success';

    await writeAudit(env, {
      actor: actor.actor, action: dryRun ? 'rollback.dry_run' : 'rollback.execute',
      zone_id: meta.zone_id, zone_name: meta.zone_name, target_type: 'snapshot',
      target_id: snapshotId, outcome,
      details: {
        source_version: meta.version, categories: cats,
        pre_snapshot_id: preSnapshot?.id,
        post_restore_version: postRestoreVersion?.version ?? null,
        totals: report.totals,
        state_diff: stateDiff.summary,
        endpoints: report.entries.map(e => ({
          category: e.category, endpoint: e.endpoint, status: e.status, ops: e.ops?.length || 0,
        })),
      },
    });

    return jsonResponse({
      snapshot: { id: meta.id, version: meta.version, zone_name: meta.zone_name },
      categories: cats,
      pre_snapshot: preSnapshot,
      post_restore_version: postRestoreVersion,
      post_restore_error: postRestoreError,
      state_diff: { summary: stateDiff.summary, changes: stateDiff.changes, truncated: stateDiff.truncated },
      report,
    });
  } catch (e) {
    // Record failed rollback attempts in the audit trail (validation errors,
    // missing snapshots, unusable tokens, execution errors).
    if (e && e.status) {
      await writeAudit(env, {
        actor: actor.actor, action: dryRun ? 'rollback.dry_run' : 'rollback.execute',
        target_type: 'snapshot', target_id: snapshotId || null, outcome: 'failed',
        details: { error: e.message },
      }).catch(() => {});
    }
    throw e;
  }
}

export async function handleAuditQuery(env, url) {
  const f = {
    zone_id: url.searchParams.get('zone_id') || null,
    actor: url.searchParams.get('actor') || null,
    action: url.searchParams.get('action') || null,
    from: url.searchParams.get('from') || null,
    to: url.searchParams.get('to') || null,
    limit: url.searchParams.get('limit'),
    offset: url.searchParams.get('offset'),
  };
  return jsonResponse(await queryAudit(env, f));
}
