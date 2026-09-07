// Unit tests for delta-based versioning (pure functions — no network).
// Run: npm test   (node test/versioning.test.mjs)

import assert from 'node:assert/strict';
import { deepDiff } from '../src/diff.js';
import {
  computeEndpointDelta, applyDelta, shouldStoreFull, reconstructState,
  endpointSetChanged, MAX_DELTA_CHAIN, VOLATILE_ENDPOINTS,
  selectPrunableVersions, autoSnapshotName, RETENTION_LIMIT, RETENTION_DAYS,
  attributionLabel,
} from '../src/versioning.js';
import { CATEGORIES } from '../src/categories.js';
import { buildTasks } from '../src/cfapi.js';

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ✓ ' + name); }
  catch (e) { failed++; console.error('  ✗ ' + name + '\n    ' + (e.message || e)); }
}

const META = (eps = []) => ({ zone_id: 'z1', zone_name: 'z', account_id: 'a', categories_requested: ['appsec'], fetched_endpoints: eps });
const ep = (cat, name, status = 'ok') => ({ catKey: cat, name, path: `zones/z1/${name}`, status });

function makeState() {
  return {
    appsec: {
      security_level: { id: 'security_level', value: 'high' },
      firewall_rules: [{ id: 'r1', paused: false, description: 'block', expression: 'ip.src eq 1.2.3.4' }],
    },
    general: { dns_records: [{ id: 'd1', type: 'A', name: 'a.z.com', content: '1.1.1.1', ttl: 300 }] },
    _meta: META([ep('appsec', 'security_level'), ep('appsec', 'firewall_rules'), ep('general', 'dns_records')]),
  };
}
const fetchedAll = new Set(['appsec|security_level', 'appsec|firewall_rules', 'general|dns_records']);

// ─── computeEndpointDelta ───────────────────────────────────────────────────

test('computeEndpointDelta: identical states → no ops', () => {
  const d = computeEndpointDelta(makeState(), makeState(), fetchedAll);
  assert.equal(d.ops.length, 0);
  assert.deepEqual(d.summary.endpoints, 0);
});

test('computeEndpointDelta: item change → one set op with full endpoint data', () => {
  const base = makeState();
  const next = makeState();
  next.appsec.security_level.value = 'medium';
  const d = computeEndpointDelta(base, next, fetchedAll);
  assert.equal(d.ops.length, 1);
  assert.equal(d.ops[0].op, 'set');
  assert.equal(d.ops[0].category, 'appsec');
  assert.equal(d.ops[0].endpoint, 'security_level');
  assert.equal(d.ops[0].data.value, 'medium');
  assert.equal(d.summary.endpoints, 1);
  assert.equal(d.summary.changed, 1);
  assert.ok(d.detail.some(c => c.path === 'appsec.security_level.value' && c.type === 'changed'));
});

test('computeEndpointDelta: new endpoint → set op, added=1', () => {
  const base = makeState();
  const next = makeState();
  next.appsec.user_agent_rules = [{ id: 'u1', description: 'x' }];
  next._meta = META([...base._meta.fetched_endpoints, ep('appsec', 'user_agent_rules')]);
  const d = computeEndpointDelta(base, next, new Set([...fetchedAll, 'appsec|user_agent_rules']));
  assert.equal(d.ops.length, 1);
  assert.equal(d.ops[0].endpoint, 'user_agent_rules');
  assert.equal(d.summary.added, 1);
});

test('computeEndpointDelta: unfetched endpoints are never touched', () => {
  const base = makeState();
  const next = makeState();
  next.appsec.firewall_rules[0].paused = true; // changed but NOT fetched this round
  const d = computeEndpointDelta(base, next, new Set(['appsec|security_level', 'general|dns_records']));
  assert.equal(d.ops.length, 0);
});

test('computeEndpointDelta: volatile endpoints never trigger versions', () => {
  const base = { account: { audit_logs: [{ id: 'a1', when: '1' }] }, _meta: META([]) };
  const next = { account: { audit_logs: [{ id: 'a2', when: '2' }] }, _meta: META([]) };
  const d = computeEndpointDelta(base, next, new Set(['account|audit_logs']));
  assert.equal(d.ops.length, 0);
  assert.ok(VOLATILE_ENDPOINTS.has('audit_logs'));
  // DEX tests are now real configuration (definitions endpoint) — not volatile
  assert.ok(!VOLATILE_ENDPOINTS.has('dex_tests'));
});

test('computeEndpointDelta: volatile endpoint still recorded when it carries real change', () => {
  // audit_logs is volatile: even if it also changed, no op
  const base = { appsec: { security_level: { value: 'high' } }, account: { audit_logs: [1] }, _meta: META([]) };
  const next = { appsec: { security_level: { value: 'low' } }, account: { audit_logs: [2] }, _meta: META([]) };
  const d = computeEndpointDelta(base, next, new Set(['appsec|security_level', 'account|audit_logs']));
  assert.equal(d.ops.length, 1);
  assert.equal(d.ops[0].endpoint, 'security_level');
});

test('computeEndpointDelta: modified_on-only noise → no ops', () => {
  const base = { appsec: { firewall_rules: [{ id: 'r1', paused: false, modified_on: 't1' }] }, _meta: META([]) };
  const next = { appsec: { firewall_rules: [{ id: 'r1', paused: false, modified_on: 't2' }] }, _meta: META([]) };
  const d = computeEndpointDelta(base, next, new Set(['appsec|firewall_rules']));
  assert.equal(d.ops.length, 0);
});

test('computeEndpointDelta: item removals counted', () => {
  const base = makeState();
  const next = makeState();
  next.general.dns_records = []; // record removed
  const d = computeEndpointDelta(base, next, fetchedAll);
  assert.equal(d.ops.length, 1);
  assert.equal(d.summary.item_removed, 1);
});

test('endpointSetChanged: detects endpoint list changes', () => {
  const m1 = META([ep('appsec', 'security_level')]);
  const m2 = META([ep('appsec', 'security_level'), ep('appsec', 'firewall_rules')]);
  const m3 = META([ep('appsec', 'security_level', 'ok')]);
  assert.equal(endpointSetChanged(m1, m2), true);
  assert.equal(endpointSetChanged(m1, m3), false); // same set, statuses equal
  assert.equal(endpointSetChanged(m1, META([ep('appsec', 'security_level', 'skipped')])), true);
});

// ─── applyDelta ────────────────────────────────────────────────────────────

test('applyDelta: set + del + meta ops', () => {
  const state = { appsec: { a: 1, b: 2 }, general: { c: 3 }, _meta: { zone_id: 'z1', old: true } };
  const delta = {
    ops: [
      { op: 'set', category: 'appsec', endpoint: 'a', data: 99 },
      { op: 'del', category: 'appsec', endpoint: 'b' },
      { op: 'meta', meta: { zone_name: 'new-name' } },
    ],
  };
  const out = applyDelta(state, delta);
  assert.equal(out.appsec.a, 99);
  assert.equal(out.appsec.b, undefined);
  assert.equal(out.general.c, 3);
  assert.equal(out._meta.zone_name, 'new-name');
  assert.equal(out._meta.old, true); // meta merges, does not replace
  assert.equal(state.appsec.a, 1);   // input untouched
  assert.equal(state.appsec.b, 2);
});

// ─── shouldStoreFull ────────────────────────────────────────────────────────

test('shouldStoreFull: chain depth threshold', () => {
  assert.equal(shouldStoreFull({ chainDepth: 5, deltaBytes: 10, baseBytes: 10000 }), false);
  assert.equal(shouldStoreFull({ chainDepth: MAX_DELTA_CHAIN, deltaBytes: 10, baseBytes: 10000 }), true);
});

test('shouldStoreFull: size ratio threshold', () => {
  assert.equal(shouldStoreFull({ chainDepth: 1, deltaBytes: 4000, baseBytes: 10000 }), false);
  assert.equal(shouldStoreFull({ chainDepth: 1, deltaBytes: 6000, baseBytes: 10000 }), true);
});

// ─── reconstructState ───────────────────────────────────────────────────────

function fakeStore() {
  const rows = new Map();   // `${zoneId}:${version}` → row
  const blobs = new Map();   // r2Key → payload
  return {
    rows, blobs,
    loadRow: async (zoneId, v) => rows.get(`${zoneId}:${v}`) || null,
    loadPayload: async (r2Key) => blobs.get(r2Key),
  };
}

test('reconstructState: full snapshot returns payload directly', async () => {
  const st = fakeStore();
  st.rows.set('z1:1', { kind: 'full', base_version: null, r2_key: 'k1', checksum: 'c1' });
  st.blobs.set('k1', { appsec: { a: 1 }, _meta: META([]) });
  const state = await reconstructState(st.loadRow, st.loadPayload, 'z1', 1);
  assert.equal(state.appsec.a, 1);
});

test('reconstructState: delta chain applies in order', async () => {
  const st = fakeStore();
  st.rows.set('z1:1', { kind: 'full', base_version: null, r2_key: 'k1', checksum: 'c1' });
  st.blobs.set('k1', { appsec: { a: 1, b: 1 }, _meta: { zone_id: 'z1', v: 'base' } });
  st.rows.set('z1:2', { kind: 'delta', base_version: 1, r2_key: 'k2', checksum: 'c2' });
  st.blobs.set('k2', { ops: [{ op: 'set', category: 'appsec', endpoint: 'a', data: 2 }] });
  st.rows.set('z1:3', { kind: 'delta', base_version: 2, r2_key: 'k3', checksum: 'c3' });
  st.blobs.set('k3', { ops: [{ op: 'set', category: 'appsec', endpoint: 'b', data: 3 }, { op: 'del', category: 'appsec', endpoint: 'a' }] });

  const state = await reconstructState(st.loadRow, st.loadPayload, 'z1', 3);
  assert.equal(state.appsec.a, undefined); // deleted by v3
  assert.equal(state.appsec.b, 3);         // set by v3
  assert.equal(state._meta.v, 'base');      // carried from full base
});

test('reconstructState: cycle detection throws', async () => {
  const st = fakeStore();
  st.rows.set('z1:2', { kind: 'delta', base_version: 3, r2_key: 'k2', checksum: 'c2' });
  st.rows.set('z1:3', { kind: 'delta', base_version: 2, r2_key: 'k3', checksum: 'c3' });
  await assert.rejects(() => reconstructState(st.loadRow, st.loadPayload, 'z1', 3), /cycle|too long|not found/i);
});

test('reconstructState: missing version throws', async () => {
  const st = fakeStore();
  await assert.rejects(() => reconstructState(st.loadRow, st.loadPayload, 'z1', 9), /not found/i);
});

// ─── Roundtrip: compute → apply equals merged state ─────────────────────────

test('roundtrip: applyDelta(computeEndpointDelta(...)) equals merged state', async () => {
  const base = makeState();
  const next = makeState();
  next.appsec.security_level.value = 'medium';
  next.appsec.firewall_rules.push({ id: 'r2', paused: false, description: 'new', expression: 'ip.src eq 5.6.7.8' });
  next.general.dns_records[0].ttl = 600;
  next._meta = META([...base._meta.fetched_endpoints, ep('appsec', 'user_agent_rules')]);
  next.appsec.user_agent_rules = [{ id: 'u1', description: 'ua' }];

  const fetched = new Set([...fetchedAll, 'appsec|user_agent_rules']);
  const delta = computeEndpointDelta(base, next, fetched);
  assert.equal(delta.ops.length, 3);

  const merged = applyDelta(base, { ops: delta.ops });

  // merged must equal `next` for every observed endpoint
  assert.deepEqual(merged.appsec, next.appsec);
  assert.deepEqual(merged.general, next.general);
  assert.equal(merged._meta.zone_id, 'z1');

  // deterministic: applying twice from the same base gives identical JSON
  assert.equal(JSON.stringify(applyDelta(base, { ops: delta.ops })), JSON.stringify(merged));
});

// ─── Retention (PAN SCM-style) ──────────────────────────────────────────────

test('selectPrunableVersions: keeps newest N non-named versions', () => {
  const now = Date.now();
  const v = n => ({ id: 'v' + n, version: n, named: 0, deleted_at: null, created_at: new Date(now - n * 1000).toISOString() });
  const versions = [v(1), v(2), v(3), v(4), v(5)];
  const prunable = selectPrunableVersions(versions, { limit: 3, maxAgeDays: 180, now });
  assert.deepEqual(prunable.sort(), ['v1', 'v2']);
});

test('selectPrunableVersions: named snapshots are never pruned', () => {
  const now = Date.now();
  const versions = [
    { id: 'a', version: 1, named: 1, deleted_at: null, created_at: new Date(now - 400 * 86400_000).toISOString() },
    { id: 'b', version: 2, named: 0, deleted_at: null, created_at: new Date(now - 3 * 1000).toISOString() },
    { id: 'c', version: 3, named: 0, deleted_at: null, created_at: new Date(now - 2 * 1000).toISOString() },
  ];
  const prunable = selectPrunableVersions(versions, { limit: 1, maxAgeDays: 30, now });
  assert.deepEqual(prunable, ['b']); // 'a' is named (pinned even at 400 days), 'c' kept as newest 1
});

test('selectPrunableVersions: prunes versions older than maxAgeDays even within limit', () => {
  const now = Date.now();
  const versions = [
    { id: 'old', version: 1, named: 0, deleted_at: null, created_at: new Date(now - 200 * 86400_000).toISOString() },
    { id: 'new', version: 2, named: 0, deleted_at: null, created_at: new Date(now - 86400_000).toISOString() },
  ];
  const prunable = selectPrunableVersions(versions, { limit: 10, maxAgeDays: 180, now });
  assert.deepEqual(prunable, ['old']);
});

test('selectPrunableVersions: limit 0 = unlimited count (age rule only)', () => {
  const now = Date.now();
  const versions = [1, 2, 3, 4].map(n => ({
    id: 'v' + n, version: n, named: 0, deleted_at: null,
    created_at: new Date(now - n * 1000).toISOString(),
  }));
  assert.deepEqual(selectPrunableVersions(versions, { limit: 0, maxAgeDays: 180, now }), []);
});

test('selectPrunableVersions: already-deleted versions are ignored', () => {
  const now = Date.now();
  const versions = [
    { id: 'gone', version: 1, named: 0, deleted_at: 'x', created_at: new Date(now - 1000).toISOString() },
    { id: 'keep', version: 2, named: 0, deleted_at: null, created_at: new Date(now - 500).toISOString() },
  ];
  assert.deepEqual(selectPrunableVersions(versions, { limit: 1, maxAgeDays: 180, now }), []);
});

test('retention defaults', () => {
  assert.equal(RETENTION_LIMIT, 200);
  assert.equal(RETENTION_DAYS, 180);
});

test('autoSnapshotName format', () => {
  const n = autoSnapshotName(new Date('2026-08-31T12:34:56Z'));
  assert.equal(n, 'config_2026-08-31-12-34-56');
  assert.ok(n.length <= 64);
});

test('computeEndpointDelta: runtime health/file-size churn → no ops', () => {
  const base = {
    network: { lb_pools: [{ id: 'p1', name: 'art', origins: [{ name: 'art', address: '34.85.7.201', healthy: false, failure_reason: 'HTTP timeout occurred' }] }] },
    account: { d1_databases: [{ uuid: 'db1', name: 'x', file_size: 65536 }] },
    _meta: META([]),
  };
  const next = {
    network: { lb_pools: [{ id: 'p1', name: 'art', origins: [{ name: 'art', address: '34.85.7.201', healthy: true, failure_reason: 'TCP timeout occurred' }] }] },
    account: { d1_databases: [{ uuid: 'db1', name: 'x', file_size: 73728 }] },
    _meta: META([]),
  };
  const d = computeEndpointDelta(base, next, new Set(['network|lb_pools', 'account|d1_databases']));
  assert.equal(d.ops.length, 0);
});

test('computeEndpointDelta: tunnel status flaps do not trigger versions', () => {
  const base = { zero_trust: { tunnels: [{ id: 't1', name: 'edge', status: 'healthy', run_at: 'x', remote_config: 'a' }] }, _meta: META([]) };
  const next = { zero_trust: { tunnels: [{ id: 't1', name: 'edge', status: 'degraded', run_at: 'y', remote_config: 'b' }] }, _meta: META([]) };
  const d = computeEndpointDelta(base, next, new Set(['zero_trust|tunnels']));
  assert.equal(d.ops.length, 0);
  // but a real tunnel config change (name) does
  const next2 = { zero_trust: { tunnels: [{ id: 't1', name: 'renamed', status: 'healthy' }] }, _meta: META([]) };
  const d2 = computeEndpointDelta(base, next2, new Set(['zero_trust|tunnels']));
  assert.equal(d2.ops.length, 1);
});

test('computeEndpointDelta: access key rotation state does not trigger versions', () => {
  const base = { zero_trust: { access_keys: { key_rotation_interval_days: 42, last_key_rotation_at: '2026-09-03T01:50:57Z', days_until_next_rotation: 41 } }, _meta: META([]) };
  const next = { zero_trust: { access_keys: { key_rotation_interval_days: 42, last_key_rotation_at: '2026-09-03T01:50:57Z', days_until_next_rotation: 40 } }, _meta: META([]) };
  const d = computeEndpointDelta(base, next, new Set(['zero_trust|access_keys']));
  assert.equal(d.ops.length, 0);
  // but a real config change (interval) does
  const next2 = { zero_trust: { access_keys: { key_rotation_interval_days: 30, last_key_rotation_at: '2026-09-03T01:50:57Z', days_until_next_rotation: 40 } }, _meta: META([]) };
  const d2 = computeEndpointDelta(base, next2, new Set(['zero_trust|access_keys']));
  assert.equal(d2.ops.length, 1);
});

test('computeEndpointDelta: DLP match counters do not trigger versions', () => {
  const mk = (n) => ({ zero_trust: { dlp_profiles: [{ id: 'd1', name: 'ccn', allowed_match_count: n }] }, _meta: META([]) });
  const d = computeEndpointDelta(mk(5), mk(6), new Set(['zero_trust|dlp_profiles']));
  assert.equal(d.ops.length, 0);
  const mk2 = (name) => ({ zero_trust: { dlp_profiles: [{ id: 'd1', name, allowed_match_count: 5 }] }, _meta: META([]) });
  assert.equal(computeEndpointDelta(mk2('ccn'), mk2('renamed'), new Set(['zero_trust|dlp_profiles'])).ops.length, 1);
});

test('computeEndpointDelta: gateway cert binding state does not trigger versions', () => {
  const mk = (bs) => ({ zero_trust: { gateway_certificates: [{ id: 'c1', name: 'loc', binding_status: bs, expires_on: '2029-11-18T12:49:00Z' }] }, _meta: META([]) });
  const d = computeEndpointDelta(mk('available'), mk('binding'), new Set(['zero_trust|gateway_certificates']));
  assert.equal(d.ops.length, 0);
});

test('computeEndpointDelta: access policy app_count does not trigger versions', () => {
  const mk = (n) => ({ zero_trust: { access_policies: [{ id: 'p1', name: 'staff', app_count: n, include: [{ email: 'a@x.com' }] }] }, _meta: META([]) });
  const d = computeEndpointDelta(mk(1), mk(4), new Set(['zero_trust|access_policies']));
  assert.equal(d.ops.length, 0);
  // but a real policy change (include) does
  const mk2 = (e) => ({ zero_trust: { access_policies: [{ id: 'p1', name: 'staff', app_count: 1, include: [{ email: e }] }] }, _meta: META([]) });
  assert.equal(computeEndpointDelta(mk2('a@x.com'), mk2('b@x.com'), new Set(['zero_trust|access_policies'])).ops.length, 1);
});

test('deepDiff: ignoreKeys option', () => {
  const d1 = deepDiff({ a: 1, flaky: 'x' }, { a: 1, flaky: 'y' });
  assert.equal(d1.changes.length, 1);
  const d2 = deepDiff({ a: 1, flaky: 'x' }, { a: 1, flaky: 'y' }, { ignoreKeys: ['flaky'] });
  assert.equal(d2.changes.length, 0);
});

// ─── Product separation (AppSec vs Cloudflare One are never mixed) ──────────

test('products: all Zero Trust endpoints belong to the One product', () => {
  const zt = CATEGORIES.find(c => c.key === 'zero_trust');
  assert.ok(zt.endpoints.length >= 20);
  assert.ok(zt.endpoints.every(ep => ep.product === 'one'));
});

test('products: DLP lives under Zero Trust', () => {
  const zt = CATEGORIES.find(c => c.key === 'zero_trust');
  assert.ok(zt.endpoints.some(ep => ep.name === 'dlp_profiles'));
  assert.ok(!CATEGORIES.find(c => c.key === 'account_sec').endpoints.some(ep => ep.name === 'dlp_profiles'));
});

test('products: zone-level WAF stays in the AppSec product', () => {
  const names = CATEGORIES.flatMap(c => c.endpoints).filter(ep => (ep.product || 'appsec') === 'appsec' && (ep.scope || 'zone') === 'zone').map(ep => ep.name);
  for (const n of ['firewall_rules', 'waf_overrides', 'dns_records', 'security_level', 'page_rules', 'cache_rules', 'dnssec']) {
    assert.ok(names.includes(n), n + ' should be appsec/zone');
  }
});

test('products: account-level WAF belongs to the AppSec product', () => {
  const acct = CATEGORIES.find(c => c.key === 'account_sec');
  assert.deepEqual(acct.endpoints.map(ep => ep.name).sort(), ['ip_access_rules_acct', 'waf_custom_rules_acct']);
  assert.ok(acct.endpoints.every(ep => (ep.product || 'appsec') === 'appsec' && ep.scope === 'account'));
});

test('products: AppSec fetch = zone-level config + account WAF, never Zero Trust', () => {
  const tasks = buildTasks('z1', 'a1', CATEGORIES.map(c => c.key), CATEGORIES, 'appsec');
  assert.ok(tasks.length >= 60);
  assert.ok(tasks.some(t => t.name === 'firewall_rules'));
  assert.ok(tasks.some(t => t.name === 'waf_custom_rules_acct'), 'account WAF custom rules are part of AppSec');
  assert.ok(tasks.some(t => t.name === 'ip_access_rules_acct'), 'account IP access rules are part of AppSec');
  assert.ok(!tasks.some(t => t.catKey === 'zero_trust'), 'AppSec fetch must never include Zero Trust');
});

test('products: AppSec fetch without an account id is zone-only', () => {
  const tasks = buildTasks('z1', '', CATEGORIES.map(c => c.key), CATEGORIES, 'appsec');
  assert.ok(tasks.length >= 55);
  assert.ok(tasks.every(t => !t.path.includes('accounts/')));
  assert.ok(!tasks.some(t => t.name === 'waf_custom_rules_acct'));
});

test('products: One fetch = pure Zero Trust, no WAF, no zone endpoints', () => {
  const tasks = buildTasks(null, 'a1', CATEGORIES.map(c => c.key), CATEGORIES, 'one');
  assert.ok(tasks.length >= 23);
  assert.ok(tasks.every(t => t.path.includes('accounts/')), 'Zero Trust is account-level only');
  assert.ok(tasks.every(t => t.catKey === 'zero_trust'));
  assert.ok(!tasks.some(t => t.name === 'waf_custom_rules_acct'), 'account WAF must NOT be in the Zero Trust product');
  assert.ok(!tasks.some(t => t.name === 'ip_access_rules_acct'));
  assert.ok(tasks.some(t => t.name === 'dlp_profiles'), 'DLP is part of Zero Trust');
  assert.ok(!tasks.some(t => t.name === 'firewall_rules'));
});

test('products: all One-product endpoints require an account id', () => {
  const bad = CATEGORIES.flatMap(c => c.endpoints).filter(ep => ep.product === 'one' && !ep.accountRequired);
  assert.deepEqual(bad, []);
});

test('products: One fetch without an account id yields no tasks', () => {
  assert.deepEqual(buildTasks(null, '', CATEGORIES.map(c => c.key), CATEGORIES, 'one'), []);
});

test('scopes: all Cloudflare One endpoints are account-scoped', () => {
  const zt = CATEGORIES.find(c => c.key === 'zero_trust');
  assert.ok(zt.endpoints.every(ep => ep.scope === 'account'));
});

test('catalog: DEX tests use the config definitions endpoint (never analytics)', () => {
  const zt = CATEGORIES.find(c => c.key === 'zero_trust');
  const dex = zt.endpoints.find(ep => ep.name === 'dex_tests');
  assert.ok(dex, 'dex_tests must exist');
  assert.ok(dex.path(null, 'a1').includes('/devices/dex_tests'), 'must use devices/dex_tests (definitions)');
  assert.ok(!dex.path(null, 'a1').includes('overview'), 'must never fetch the analytics overview');
});

test('catalog: analytics/licensing endpoints are excluded', () => {
  const paths = CATEGORIES.flatMap(c => c.endpoints).map(ep => ep.path('z', 'a'));
  for (const p of paths) {
    assert.ok(!p.includes('dex/tests/overview'), 'DEX analytics must not be fetched');
    assert.ok(!p.includes('/seats'), 'seat/licensing usage must not be fetched');
    assert.ok(!p.includes('/gateway/categories'), 'static URL-category catalog must not be fetched');
  }
});

test('attributionLabel: actors and actions from audit entries', () => {
  const entries = [
    { when: '2026-08-31T10:00:00Z', actor: { email: 'admin@x.com' }, action: { type: 'Firewall Rules updated' } },
    { when: '2026-08-31T10:01:00Z', actor: { email: 'admin@x.com' }, action: { type: 'Access policy updated' } },
    { when: '2026-08-31T10:02:00Z', actor: { email: 'dev@x.com' }, action: { type: 'Firewall Rules updated' } },
  ];
  const label = attributionLabel(entries);
  assert.ok(label.startsWith('Auto: by admin@x.com, dev@x.com — '));
  assert.ok(label.includes('Firewall Rules updated'));
  assert.ok(label.includes('Access policy updated'));
});

test('attributionLabel: empty entries → null, missing fields → fallback', () => {
  assert.equal(attributionLabel([]), null);
  assert.equal(attributionLabel(null), null);
  const label = attributionLabel([{ when: 'x' }, { when: 'y' }]);
  assert.equal(label, 'Auto: change detected via Cloudflare audit log');
});

test('attributionLabel: truncates very long labels', () => {
  const entries = Array.from({ length: 40 }, (_, i) => ({
    when: 'x', actor: { email: 'user' + i + '@very-long-domain-name.example.com' }, action: { type: 'Some very long configuration action type number ' + i },
  }));
  const label = attributionLabel(entries, 140);
  assert.ok(label.length <= 140);
  assert.ok(label.endsWith('…'));
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
