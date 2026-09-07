// ─── Rollback engine ─────────────────────────────────────────────────────────
// Plans and applies the operations needed to restore a snapshot's configuration
// onto the live Cloudflare account/zone.
//
// Design:
//  - classify(path) maps a fetched endpoint path to a planner type (or null =
//    view-only resource that is reported but never written back).
//  - Planners are PURE functions of (snapshot data, live data) → op list, so
//    they are unit-testable and a dry run executes zero writes.
//  - Ops run through executeOps() with bounded concurrency; each result is
//    captured for the report and the audit trail.
//  - After execution every endpoint is re-fetched and verified against the
//    snapshot.
//
// Safety guards:
//  - List endpoints at the page-size cap (possible truncation) are refused.
//  - Endpoints fetched with action= filters (partial lists) are view-only.
//  - Warnings are attached for resources whose secrets cannot be restored
//    (service tokens, tunnels, IdPs).

import { cf, toItems, enrichGatewayLists } from './cfapi.js';
import { truncateStr } from './diff.js';

// Keys stripped from write-back bodies (server-managed fields).
const READ_ONLY_KEYS = new Set([
  'id', 'created_on', 'modified_on', 'created_at', 'modified_at', 'created', 'updated',
  'zone_id', 'zone_name', 'proxiable', 'meta', 'etag', 'version',
  'last_updated', 'ref', 'deleted', 'checksum', 'read_only', 'editable',
]);

const GATEWAY_READONLY = ['dashboard_url', 'smh_url', 'gateway_disabled', 'current_version', 'account_configured', 'cache_bypass', 'permission_groups'];

function clean(obj, extra = []) {
  if (Array.isArray(obj)) return obj.map(x => clean(x, extra));
  if (obj === null || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (READ_ONLY_KEYS.has(k) || extra.includes(k)) continue;
    out[k] = clean(v, extra);
  }
  return out;
}

function cleanEqual(a, b, extra = []) {
  return JSON.stringify(clean(a, extra)) === JSON.stringify(clean(b, extra));
}

function describeItem(item) {
  if (!item || typeof item !== 'object') return String(item);
  const label = item.description || item.name || item.pattern || item.domain
    || (item.target && (item.target.value || item.target.content))
    || (item.expression && truncateStr(item.expression, 50))
    || item.id || 'item';
  return truncateStr(String(label), 80);
}

// ─── Endpoint classification ────────────────────────────────────────────────

// Human-facing notes about HOW each endpoint restores (shown on the Reference
// page). Keyed by catalog endpoint name; the classify() type is authoritative
// for behavior, these strings explain it.
export const RESTORE_NOTES = {
  'dns_records': 'Matched by type + name; changed content is paired with existing records to avoid delete/create downtime.',
  'gateway_lists': 'List metadata restored via PUT, items appended/removed individually via the list PATCH API.',
  'access_service_tokens': 'Restored tokens get NEW client secrets — integrations must be updated.',
  'tunnels': 'Restored tunnels get NEW connector tokens — cloudflared must be re-registered.',
  'access_idp': 'Provider secrets are not always returned — re-created IdPs may need manual re-configuration.',
  'access_apps': 'Includes inline policies; reusable policy bindings are restored by id.',
  'dex_tests': 'Created/updated/deleted individually via the devices/dex_tests API (keyed by test_id).',
  'waf_custom_rules_acct': 'Restored via the phase entrypoint (all rules replaced as a set).',
  'ip_access_rules_acct': 'Per-rule create/update/delete across the whole account.',
  'waf_managed_rules': 'Per-package PATCH (sensitivity / action / detection mode).',
};

export function classify(path) {
  const query = path.includes('?') ? path.slice(path.indexOf('?') + 1) : '';
  const base = path.split('?')[0];
  let m;

  // Filtered lists (e.g. old gateway rules?action=... fetches) are partial
  // views and can never be reconciled safely.
  if (/(?:^|[?&])action=/.test(path)) {
    return { type: 'view_only', base, reason: 'filtered fetch (action=) — restoring a partial list would delete the rest' };
  }

  // Zone settings: zones/:id/settings/<name>
  if ((m = base.match(/^zones\/[^/]+\/settings\/([a-z0-9_]+)$/i))) {
    return { type: 'setting', base, name: m[1] };
  }

  // Account-level phase ruleset list (e.g. custom WAF rules) → entrypoint form
  if (/^accounts\/[^/]+\/rulesets$/.test(base) && /(?:^|&)phase=/.test(query)) {
    const phase = (query.match(/(?:^|&)phase=([^&]+)/) || [])[1];
    if (phase !== 'http_request_firewall_custom') {
      return { type: 'view_only', base, reason: `phase ${phase} restore via entrypoint is not supported` };
    }
    const accountPath = base.replace(/\/rulesets$/, '');
    return { type: 'phaseRuleset', phase, base: `${accountPath}/rulesets/phases/${phase}/entrypoint` };
  }

  // Phase entrypoint rulesets (transform, redirect, cache, config, ddos)
  if ((m = base.match(/\/rulesets\/phases\/([^/]+)\/entrypoint$/))) {
    return { type: 'phaseRuleset', phase: m[1], base };
  }

  if (base.endsWith('/dns_records')) return { type: 'dns', base, pageGuard: 500 };
  if (base.endsWith('/gateway/lists')) return { type: 'gatewayLists', base, pageGuard: 100 };
  if (base.endsWith('/devices/dex_tests')) return { type: 'collection', base, idKey: 'test_id', pageGuard: 100 };
  if (base.endsWith('/firewall/rules')) return { type: 'collection', base, createAsArray: true, pageGuard: 100 };
  if (base.endsWith('/firewall/waf/overrides')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/firewall/ua_rules')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/firewall/lockdowns')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/rate_limits')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/pagerules')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/firewall/access_rules/rules')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/firewall/waf/packages')) return { type: 'collection', base, pageGuard: 100, updateMethod: 'PATCH' };
  if (base.endsWith('/bot_management')) return { type: 'singleton', base, method: 'PUT' };
  if (base.endsWith('/speed_brain')) return { type: 'singleton', base, method: 'PUT' };
  if (base.endsWith('/managed_headers')) return { type: 'managedHeaders', base };
  if (base.endsWith('/cache/tiered_cache_smart_topology_enable')) return { type: 'singleton', base, method: 'POST' };
  if (base.endsWith('/cache/cache_reserve')) return { type: 'singleton', base, method: 'PUT' };

  // ── Zero Trust ──
  if (base.endsWith('/access/organizations')) return { type: 'singleton', base, method: 'PUT' };
  if (base.endsWith('/access/apps')) {
    return { type: 'collection', base, pageGuard: 100, keepNestedIds: ['policies'] };
  }
  if (base.endsWith('/access/policies')) {
    // app_count is a derived counter of apps linking each policy — runtime, not config
    return { type: 'collection', base, pageGuard: 100, strip: ['app_count'] };
  }
  if (base.endsWith('/access/groups')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/access/service_tokens')) {
    return {
      type: 'collection', base, pageGuard: 100,
      strip: ['client_secret', 'token', 'secret', 'last_seen_at'],
      warnCreate: 'Restored service tokens receive NEW client secrets — any integration using the old token secret must be updated.',
    };
  }
  if (base.endsWith('/access/identity_providers')) {
    return {
      type: 'collection', base, pageGuard: 100,
      warnCreate: 'Identity provider secrets are not always returned by the API — re-created providers may require manual re-configuration.',
    };
  }
  if (base.endsWith('/cfd_tunnel')) {
    return {
      type: 'collection', base, pageGuard: 100,
      strip: ['tunnel_secret', 'connections', 'status', 'remote_config', 'run_at'],
      warnCreate: 'Restored tunnels receive NEW connector tokens — cloudflared connectors must be re-registered with the new token.',
    };
  }
  if (base.endsWith('/teamnet/routes')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/teamnet/virtual_networks')) return { type: 'collection', base, pageGuard: 100 };
  if (/^accounts\/[^/]+\/gateway$/.test(base)) return { type: 'gatewaySettings', base };
  if (base.endsWith('/gateway/locations')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/gateway/lists')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/gateway/rules')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/gateway/proxy_endpoints')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/devices/posture')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/devices/posture/integrations')) return { type: 'collection', base, pageGuard: 100 };
  if (base.endsWith('/devices/settings')) return { type: 'singleton', base, method: 'PATCH' };
  if (base.endsWith('/devices/policy/fallback_domains')) return { type: 'listSingleton', base };
  if (base.endsWith('/zt_risk_scoring/settings')) return { type: 'singleton', base, method: 'PUT' };

  return null; // view-only
}

// ─── Planners (pure) ────────────────────────────────────────────────────────

function planSetting(cls, snapData, liveData) {
  const snapValue = snapData?.result?.value ?? snapData?.value;
  const liveValue = liveData?.result?.value ?? liveData?.value;
  if (snapValue === undefined) return { error: 'snapshot has no value' };
  if (JSON.stringify(snapValue) === JSON.stringify(liveValue)) return { ops: [], unchanged: 1 };
  return {
    ops: [{
      method: 'PATCH', path: cls.base, body: { value: snapValue }, kind: 'set',
      describe: `${cls.name}: ${JSON.stringify(liveValue)} → ${JSON.stringify(snapValue)}`,
    }],
  };
}

// Restore nested object ids (e.g. Access app policies) that clean() stripped.
function withNestedIds(cls, item) {
  const extra = [...(cls.strip || [])];
  if (cls.idKey && cls.idKey !== 'id') extra.push(cls.idKey);
  const body = clean(item, extra);
  for (const key of cls.keepNestedIds || []) {
    const orig = item?.[key];
    if (Array.isArray(orig) && Array.isArray(body[key])) {
      body[key] = body[key].map((c, i) => (orig[i] && orig[i].id !== undefined ? { ...c, id: orig[i].id } : c));
    }
  }
  return body;
}

// ── Gateway lists (Zero Trust) ──────────────────────────────────────────────
// List metadata (name/description/type) is restored via PUT; items are
// restored via PATCH {append, remove} on the same list. Item identity is the
// value (description is part of the item's config).

// Normalize items to {value, description?} (what the API accepts for append).
function normalizeListItems(items) {
  return (items || []).map(i => (i && typeof i === 'object'
    ? { value: i.value, ...(i.description ? { description: i.description } : {}) }
    : { value: i }));
}

// Multiset delta from live → snapshot by (value, description) pairs:
//   append  = snapshot items not present in live (full {value, description})
//   remove  = values of live items not present in the snapshot
function listItemsDelta(liveItems, snapItems) {
  const live = new Map(); // pairKey → {n, value}
  for (const i of normalizeListItems(liveItems)) {
    const k = JSON.stringify([i.value, i.description || '']);
    const e = live.get(k) || { n: 0, value: i.value };
    e.n++;
    live.set(k, e);
  }
  const append = [];
  for (const i of normalizeListItems(snapItems)) {
    const k = JSON.stringify([i.value, i.description || '']);
    const e = live.get(k);
    if (e && e.n > 0) e.n--;  // matches a live item — kept in place
    else append.push(i);      // not in live → append from snapshot
  }
  const remove = [];
  for (const e of live.values()) {
    for (let i = 0; i < e.n; i++) remove.push(e.value); // surplus live items → remove by value
  }
  return { append, remove };
}

function listItemsEqual(a, b) {
  const sig = (items) => normalizeListItems(items)
    .map(i => JSON.stringify([i.value, i.description || ''])).sort();
  return JSON.stringify(sig(a)) === JSON.stringify(sig(b));
}

function listMetaClean(list) {
  return clean(list, ['items', 'count', 'updated_at']);
}

function planGatewayLists(cls, snapData, liveData) {
  const snapItems = toItems(snapData);
  const liveItems = toItems(liveData);
  const guard = cls.pageGuard || 100;
  if (snapItems.length >= guard || liveItems.length >= guard) {
    return { error: `list is at the page-size cap (≥${guard}) — pagination not supported, refusing to reconcile for safety` };
  }
  const liveById = new Map(liveItems.map(i => [String(i.id), i]));
  const snapIds = new Set(snapItems.map(i => String(i.id)));
  const creates = [], updates = [], deletes = [];
  let unchanged = 0;

  for (const item of snapItems) {
    const live = liveById.get(String(item.id));
    if (!live) {
      creates.push(item);
      continue;
    }
    let changed = false;
    if (JSON.stringify(listMetaClean(item)) !== JSON.stringify(listMetaClean(live))) {
      updates.push({ method: 'PUT', path: `${cls.base}/${item.id}`, body: listMetaClean(item),
        describe: `update list ${describeItem(item)}`, kind: 'update' });
      changed = true;
    }
    if (!listItemsEqual(item.items, live.items)) {
      const { append, remove } = listItemsDelta(live.items, item.items);
      const body = {};
      if (append.length) body.append = append;
      if (remove.length) body.remove = remove;
      updates.push({ method: 'PATCH', path: `${cls.base}/${item.id}`, body,
        describe: `restore items of list ${item.name || item.id} (+${append.length} −${remove.length})`, kind: 'update' });
      changed = true;
    }
    if (!changed) unchanged++;
  }

  const createOps = creates.map(item => {
    const ops = [{ method: 'POST', path: cls.base, body: listMetaClean(item),
      describe: `create list ${describeItem(item)}`, kind: 'create' }];
    if ((item.items || []).length) {
      ops.push({ method: 'PATCH', path: cls.base, body: { append: normalizeListItems(item.items) },
        describe: `add ${item.items.length} item(s) to new list ${item.name}`, kind: 'create' });
    }
    return ops;
  }).flat();

  for (const item of liveItems) {
    if (!snapIds.has(String(item.id))) {
      deletes.push({ method: 'DELETE', path: `${cls.base}/${item.id}`, describe: `delete list ${describeItem(item)}`, kind: 'delete' });
    }
  }

  return { ops: [...createOps, ...updates, ...deletes], unchanged };
}


function planCollection(cls, snapData, liveData) {
  const snapItems = toItems(snapData);
  const liveItems = toItems(liveData);
  const guard = cls.pageGuard || 100;
  if (snapItems.length >= guard || liveItems.length >= guard) {
    return { error: `list is at the page-size cap (≥${guard}) — pagination not supported, refusing to reconcile for safety` };
  }

  const idKey = cls.idKey || 'id';
  const liveById = new Map(liveItems.map(i => [String(i[idKey]), i]));
  const snapIds = new Set(snapItems.map(i => String(i[idKey])));
  const creates = [], updates = [], deletes = [];
  let unchanged = 0;

  for (const item of snapItems) {
    const live = liveById.get(String(item[idKey]));
    if (!live) { creates.push(item); continue; }
    if (cleanEqual(item, live, cls.strip)) { unchanged++; continue; }
    updates.push({
      method: cls.updateMethod || 'PUT', path: `${cls.base}/${item[idKey]}`, body: withNestedIds(cls, item),
      describe: `update ${describeItem(item)}`, kind: 'update',
    });
  }

  const extraCreateStrip = idKey === 'id' ? [] : [idKey];
  const createOps = creates.length
    ? (cls.createAsArray
      ? [{ method: 'POST', path: cls.base, body: creates.map(i => clean(i, cls.strip, extraCreateStrip)), describe: `create ${creates.length} rule(s): ${creates.map(describeItem).join(', ')}`, kind: 'create', warning: cls.warnCreate }]
      : creates.map(i => ({ method: 'POST', path: cls.base, body: clean(i, cls.strip, extraCreateStrip), describe: `create ${describeItem(i)}`, kind: 'create', warning: cls.warnCreate })))
    : [];

  for (const item of liveItems) {
    if (!snapIds.has(String(item[idKey]))) {
      deletes.push({ method: 'DELETE', path: `${cls.base}/${item[idKey]}`, describe: `delete ${describeItem(item)}`, kind: 'delete' });
    }
  }

  const warnings = cls.warnCreate && creates.length ? [cls.warnCreate] : [];
  return { ops: [...createOps, ...updates, ...deletes], unchanged, warnings };
}

function planDns(cls, snapData, liveData) {
  const snapItems = toItems(snapData);
  const liveItems = toItems(liveData);
  if (snapItems.length >= 500 || liveItems.length >= 500) {
    return { error: 'DNS list is at the page-size cap (≥500) — refusing to reconcile for safety' };
  }

  const groups = new Map();
  const keyOf = r => `${r.type}|${String(r.name).toLowerCase()}`;
  for (const r of snapItems) { const k = keyOf(r); if (!groups.has(k)) groups.set(k, { snap: [], live: [] }); groups.get(k).snap.push(r); }
  for (const r of liveItems) { const k = keyOf(r); if (!groups.has(k)) groups.set(k, { snap: [], live: [] }); groups.get(k).live.push(r); }

  const ops = [];
  let unchanged = 0;

  for (const [, g] of groups) {
    const liveList = [...g.live];
    const pending = [];

    // 1) exact content matches — update ttl/proxied/etc. if the rest differs
    for (const s of g.snap) {
      const idx = liveList.findIndex(l => l.content === s.content);
      if (idx >= 0) {
        const l = liveList.splice(idx, 1)[0];
        if (cleanEqual(s, l)) unchanged++;
        else ops.push({ method: 'PUT', path: `${cls.base}/${l.id}`, body: clean(s), describe: `update ${s.type} ${s.name}`, kind: 'update' });
      } else pending.push(s);
    }

    // 2) pair leftovers by position (handles changed record content without
    //    delete/create downtime)
    for (let i = 0; i < pending.length && i < liveList.length; i++) {
      const s = pending[i], l = liveList[i];
      ops.push({
        method: 'PUT', path: `${cls.base}/${l.id}`, body: clean(s),
        describe: `update ${s.type} ${s.name} (${truncateStr(String(l.content))} → ${truncateStr(String(s.content))})`,
        kind: 'update',
      });
    }
    // 3) snapshot records with nothing to pair → create
    for (let i = liveList.length; i < pending.length; i++) {
      const s = pending[i];
      ops.push({ method: 'POST', path: cls.base, body: clean(s), describe: `create ${s.type} ${s.name}`, kind: 'create' });
    }
    // 4) live records with nothing to pair → delete
    for (let i = pending.length; i < liveList.length; i++) {
      const l = liveList[i];
      ops.push({ method: 'DELETE', path: `${cls.base}/${l.id}`, describe: `delete ${l.type} ${l.name} (${truncateStr(String(l.content))})`, kind: 'delete' });
    }
  }

  return { ops, unchanged };
}

function planPhaseRuleset(cls, snapData, liveData) {
  const snapRuleset = Array.isArray(snapData) ? snapData[0] : snapData;
  const liveRuleset = Array.isArray(liveData) ? liveData[0] : liveData;
  const snapRules = snapRuleset?.rules || [];
  const liveRules = liveRuleset?.rules || [];

  const same = snapRules.length === liveRules.length &&
    snapRules.every((r, i) => JSON.stringify(clean(r)) === JSON.stringify(clean(liveRules[i])));
  if (same) return { ops: [], unchanged: 1 };

  const liveIds = new Set(liveRules.map(r => String(r.id)));
  const rules = snapRules.map(r => {
    const c = clean(r);
    if (r.id !== undefined && liveIds.has(String(r.id))) c.id = r.id; // preserve identity of still-existing rules
    return c;
  });
  return {
    ops: [{
      method: 'PUT', path: cls.base, body: { rules },
      describe: `restore ${rules.length} rule(s) in phase ${cls.phase} (live has ${liveRules.length})`, kind: 'set',
    }],
  };
}

function planSingleton(cls, snapData, liveData) {
  const target = snapData?.result ?? snapData;
  const liveVal = liveData?.result ?? liveData;
  if (target == null) return { error: 'snapshot has no data' };
  if (cleanEqual(target, liveVal)) return { ops: [], unchanged: 1 };
  return {
    ops: [{
      method: cls.method || 'PUT', path: cls.base, body: clean(target),
      describe: `restore ${cls.base.split('/').slice(-2).join('/')}`, kind: 'set',
    }],
  };
}

function planGatewaySettings(cls, snapData, liveData) {
  const target = snapData?.result ?? snapData;
  const liveVal = liveData?.result ?? liveData;
  if (target == null) return { error: 'snapshot has no data' };
  if (cleanEqual(target, liveVal, GATEWAY_READONLY)) return { ops: [], unchanged: 1 };
  return {
    ops: [{
      method: 'PATCH', path: `${cls.base}/configuration`, body: clean(target, GATEWAY_READONLY),
      describe: 'restore Zero Trust gateway configuration', kind: 'set',
    }],
  };
}

function extractMh(d) {
  const r = d?.result ?? d;
  const mh = r?.managed_headers ?? r ?? {};
  const ids = (arr) => (Array.isArray(arr) ? arr : []).map(x => (typeof x === 'string' ? x : x?.id)).filter(Boolean);
  return { enabled: ids(mh.enabled || mh.enabled_features), disabled: ids(mh.disabled || mh.disabled_features) };
}

function planManagedHeaders(cls, snapData, liveData) {
  const snap = extractMh(snapData);
  const live = extractMh(liveData);
  if (JSON.stringify(snap) === JSON.stringify(live)) return { ops: [], unchanged: 1 };
  return {
    ops: [{
      method: 'PATCH', path: cls.base, body: { managed_headers: snap },
      describe: `managed headers: enabled=[${snap.enabled.join(',')}] disabled=[${snap.disabled.join(',')}]`, kind: 'set',
    }],
  };
}

function planListSingleton(cls, snapData, liveData) {
  const snapList = toItems(snapData);
  const liveList = toItems(liveData);
  const norm = (l) => JSON.stringify(l.map(x => clean(x, cls.strip)).map(JSON.stringify).sort());
  if (norm(snapList) === norm(liveList)) return { ops: [], unchanged: 1 };
  return {
    ops: [{
      method: 'PUT', path: cls.base, body: snapList.map(x => clean(x, cls.strip)),
      describe: `restore list (${snapList.length} entries)`, kind: 'set',
    }],
  };
}

export function planEndpoint(cls, snapData, liveData) {
  switch (cls.type) {
    case 'setting': return planSetting(cls, snapData, liveData);
    case 'gatewayLists': return planGatewayLists(cls, snapData, liveData);
    case 'collection': return planCollection(cls, snapData, liveData);
    case 'dns': return planDns(cls, snapData, liveData);
    case 'phaseRuleset': return planPhaseRuleset(cls, snapData, liveData);
    case 'singleton': return planSingleton(cls, snapData, liveData);
    case 'gatewaySettings': return planGatewaySettings(cls, snapData, liveData);
    case 'managedHeaders': return planManagedHeaders(cls, snapData, liveData);
    case 'listSingleton': return planListSingleton(cls, snapData, liveData);
    default: return { error: `unsupported type ${cls.type}` };
  }
}

// ─── Execution ──────────────────────────────────────────────────────────────

export async function executeOps(token, ops, concurrency = 4) {
  const results = new Array(ops.length);
  let i = 0;
  async function worker() {
    while (i < ops.length) {
      const idx = i++;
      const op = ops[idx];
      try {
        const r = await cf(op.method, op.path, token, op.body);
        const ok = r.ok && r.json?.success !== false;
        results[idx] = {
          describe: op.describe, kind: op.kind, method: op.method, path: op.path, ok,
          status: r.status,
          error: ok ? null : (r.json?.errors?.map(e => e.message || e.code).join('; ') || `HTTP ${r.status}`),
        };
      } catch (e) {
        results[idx] = { describe: op.describe, kind: op.kind, method: op.method, path: op.path, ok: false, status: 0, error: String(e?.message || e) };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ops.length || 1) }, worker));
  return results;
}

// ─── Verification ──────────────────────────────────────────────────────────

function normVerify(cls, data) {
  switch (cls.type) {
    case 'setting':
      return JSON.stringify(data?.result?.value ?? data?.value ?? null);
    case 'dns':
    case 'collection':
    case 'listSingleton': {
      const items = toItems(data);
      return JSON.stringify(items.map(x => clean(x, cls.strip)).map(JSON.stringify).sort());
    }
    case 'gatewayLists': {
      // lists + their items, order-insensitive, volatile/derived keys stripped
      const items = toItems(data);
      return JSON.stringify(items.map(l => JSON.stringify({
        list: clean(l, ['items', 'count', 'updated_at']),
        items: normalizeListItems(l.items).map(i => JSON.stringify([i.value, i.description || ''])).sort(),
      })).sort());
    }
    case 'phaseRuleset': {
      const rs = Array.isArray(data) ? data[0] : data;
      return JSON.stringify((rs?.rules || []).map(r => clean(r)));
    }
    case 'singleton':
      return JSON.stringify(clean(data?.result ?? data));
    case 'gatewaySettings':
      return JSON.stringify(clean(data?.result ?? data, GATEWAY_READONLY));
    case 'managedHeaders':
      return JSON.stringify(extractMh(data));
    default:
      return null;
  }
}

async function verifyEndpoint(token, cls, snapData) {
  let getPath = cls.base;
  if (cls.type === 'dns') getPath = `${cls.base}?per_page=500`;
  else if (cls.type === 'collection' || cls.type === 'listSingleton' || cls.type === 'gatewayLists') getPath = `${cls.base}?per_page=${cls.pageGuard || 100}`;

  const res = await cf('GET', getPath, token);
  if (!res.ok || !res.json || res.json.success === false) {
    // A 404 on a phase entrypoint means "no ruleset for this phase yet" —
    // that verifies cleanly when the snapshot has no rules either.
    if (res.status === 404 && cls.type === 'phaseRuleset') {
      const a = normVerify(cls, snapData);
      const b = normVerify(cls, { rules: [] });
      return a === b ? { verified: true } : { verified: false, note: 'live state still differs from snapshot' };
    }
    return { verified: false, note: `verification fetch failed (${res.status})` };
  }
  let result = res.json.result;
  // Gateway lists must be verified WITH their items
  if (cls.type === 'gatewayLists' && Array.isArray(result)) {
    const accountId = (cls.base.match(/^accounts\/([^/]+)\//) || [])[1];
    if (accountId) result = await enrichGatewayLists(token, accountId, result);
  }
  const a = normVerify(cls, snapData);
  const b = normVerify(cls, result);
  if (a === b) return { verified: true };
  return { verified: false, note: 'live state still differs from snapshot' };
}

// ─── Main entry ────────────────────────────────────────────────────────────
// payload: full snapshot payload; live: { data, statuses } from
// fetchLiveFromSnapshot(); dryRun: plan only (no writes).
export async function runRollback({ token, payload, categories, dryRun, live }) {
  const catSet = new Set(categories);
  const eps = (payload._meta?.fetched_endpoints || []).filter(e => e.status === 'ok');
  const entries = [];

  for (const ep of eps) {
    if (catSet.size && !catSet.has(ep.catKey)) continue;
    const snapData = payload[ep.catKey]?.[ep.name];
    const entry = { category: ep.catKey, endpoint: ep.name, path: ep.path, ops: [], unchanged: 0, status: 'view_only', warnings: [] };

    const cls = classify(ep.path);
    if (!cls) { entry.note = 'view-only resource (not restorable)'; entries.push(entry); continue; }
    if (cls.type === 'view_only') { entry.note = cls.reason; entries.push(entry); continue; }
    if (snapData === undefined) { entry.status = 'no_data'; entry.note = 'no data in snapshot'; entries.push(entry); continue; }

    const liveStatus = live.statuses.find(s => s.catKey === ep.catKey && s.name === ep.name);
    let liveData = live.data?.[ep.catKey]?.[ep.name];

    // A 404 on a phase entrypoint means "no ruleset for this phase yet" —
    // restoring will create it. Only this type tolerates a missing live value.
    if (liveData === undefined && cls.type === 'phaseRuleset' && liveStatus?.http === 404) liveData = { rules: [] };

    if (liveData === undefined) {
      entry.status = 'skipped';
      entry.note = `live state unavailable (${liveStatus?.status || 'not fetched'})`;
      entries.push(entry); continue;
    }

    let plan;
    try { plan = planEndpoint(cls, snapData, liveData); }
    catch (e) { plan = { error: String(e?.message || e) }; }

    if (plan.error) { entry.status = 'error'; entry.note = plan.error; entries.push(entry); continue; }
    entry.ops = plan.ops || [];
    entry.unchanged = plan.unchanged || 0;
    entry.warnings = plan.warnings || [];
    entry.status = entry.ops.length ? 'planned' : 'unchanged';
    entries.push(entry);
  }

  if (dryRun) {
    return {
      dry_run: true,
      entries: entries.map(e => ({ ...e, ops: e.ops.map(({ describe, kind, warning }) => ({ describe, kind, warning })) })),
      totals: totals(entries, null),
    };
  }

  // Execute per endpoint
  for (const entry of entries) {
    if (entry.status !== 'planned') continue;
    const results = await executeOps(token, entry.ops);
    entry.op_results = results;
    entry.status = results.every(r => r.ok) ? 'restored' : 'partial';
  }

  // Verify restored state against the snapshot
  for (const entry of entries) {
    if (!['restored', 'partial', 'unchanged'].includes(entry.status)) continue;
    const cls = classify(entry.path);
    if (!cls || cls.type === 'view_only') continue;
    const snapData = payload[entry.category]?.[entry.endpoint];
    try { entry.verification = await verifyEndpoint(token, cls, snapData); }
    catch (e) { entry.verification = { verified: false, note: String(e?.message || e) }; }
  }

  return { dry_run: false, entries, totals: totals(entries, entries.flatMap(e => e.op_results || [])) };
}

function totals(entries, opResults) {
  const t = {
    endpoints_total: entries.length,
    restored: 0, partial: 0, planned: 0, unchanged: 0,
    view_only: 0, skipped: 0, error: 0, no_data: 0,
    ops_total: 0, ops_ok: 0, ops_failed: 0,
    verified: 0, not_verified: 0,
  };
  for (const e of entries) {
    if (t[e.status] !== undefined) t[e.status]++;
    t.ops_total += e.ops?.length || 0;
    if (e.verification) { e.verification.verified ? t.verified++ : t.not_verified++; }
  }
  if (opResults) for (const r of opResults) { r.ok ? t.ops_ok++ : t.ops_failed++; }
  return t;
}
