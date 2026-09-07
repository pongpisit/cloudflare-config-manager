// Unit tests for the rollback planners and diff engine (pure functions — no network).
// Run: npm test   (node test/rollback.test.mjs)

import assert from 'node:assert/strict';
import { deepDiff, diffConfigs, summarizeChanges, stableKey } from '../src/diff.js';
import { classify, planEndpoint, RESTORE_NOTES } from '../src/rollback.js';
import { CATEGORIES } from '../src/categories.js';

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ✓ ' + name); }
  catch (e) { failed++; console.error('  ✗ ' + name + '\n    ' + (e.message || e)); }
}

// ─── deepDiff ───────────────────────────────────────────────────────────────

test('deepDiff: scalar change', () => {
  const d = deepDiff({ value: 'on' }, { value: 'off' });
  assert.equal(d.changes.length, 1);
  assert.equal(d.changes[0].type, 'changed');
  assert.equal(d.changes[0].before, 'on');
  assert.equal(d.changes[0].after, 'off');
});

test('deepDiff: added / removed keys', () => {
  const d = deepDiff({ a: 1, gone: 2 }, { a: 1, fresh: 3 });
  const types = d.changes.map(c => c.type).sort();
  assert.deepEqual(types, ['added', 'removed']);
});

test('deepDiff: ignores volatile keys', () => {
  const d = deepDiff({ value: 1, modified_on: 'x' }, { value: 1, modified_on: 'y' });
  assert.equal(d.changes.length, 0);
});

test('deepDiff: id-keyed array diff', () => {
  const a = [{ id: 1, v: 'x' }, { id: 2, v: 'y' }];
  const b = [{ id: 2, v: 'y' }, { id: 3, v: 'z' }];
  const d = deepDiff(a, b);
  const types = d.changes.map(c => c.type).sort();
  assert.deepEqual(types, ['added', 'removed']);
});

test('deepDiff: truncation flag', () => {
  const a = {}; const b = {};
  for (let i = 0; i < 600; i++) { a['k' + i] = 1; b['k' + i] = 2; }
  const d = deepDiff(a, b, { maxChanges: 10 });
  assert.equal(d.changes.length, 10);
  assert.equal(d.truncated, true);
});

test('diffConfigs: per-endpoint paths and skip', () => {
  const a = { appsec: { firewall_rules: [{ id: 1, paused: false }] } };
  const b = { appsec: { firewall_rules: [{ id: 1, paused: true }] } };
  const d = diffConfigs(a, b);
  assert.equal(d.changes.length, 1);
  assert.ok(d.changes[0].path.startsWith('appsec.firewall_rules'));
  const d2 = diffConfigs(a, b, { skip: new Set(['appsec|firewall_rules']) });
  assert.equal(d2.changes.length, 0);
  assert.equal(d2.skipped.length, 1);
});

test('summarizeChanges', () => {
  const s = summarizeChanges([{ type: 'added' }, { type: 'removed' }, { type: 'changed' }, { type: 'added' }]);
  assert.deepEqual(s, { added: 2, removed: 1, changed: 1 });
});

// ─── classify ───────────────────────────────────────────────────────────────

test('classify: zone settings', () => {
  const c = classify('zones/abc/settings/security_level');
  assert.equal(c.type, 'setting');
  assert.equal(c.name, 'security_level');
});

test('classify: firewall rules + dns + phases', () => {
  assert.equal(classify('zones/abc/firewall/rules?per_page=100').type, 'collection');
  assert.equal(classify('zones/abc/dns_records?per_page=500').type, 'dns');
  assert.equal(classify('zones/abc/rulesets/phases/http_request_transform/entrypoint').type, 'phaseRuleset');
});

test('classify: account custom WAF rules → entrypoint', () => {
  const c = classify('accounts/acc1/rulesets?phase=http_request_firewall_custom');
  assert.equal(c.type, 'phaseRuleset');
  assert.equal(c.base, 'accounts/acc1/rulesets/phases/http_request_firewall_custom/entrypoint');
});

test('classify: other phases not restorable', () => {
  assert.equal(classify('accounts/acc1/rulesets?phase=magic_transit').type, 'view_only');
});

test('classify: filtered gateway rules are view-only (old snapshots)', () => {
  const c = classify('accounts/acc1/gateway/rules?action=block&dns=false');
  assert.equal(c.type, 'view_only');
});

test('classify: CDN cache toggles are restorable singletons', () => {
  const tc = classify('zones/z/cache/tiered_cache_smart_topology_enable');
  assert.equal(tc.type, 'singleton');
  assert.equal(tc.method, 'POST');
  const cr = classify('zones/z/cache/cache_reserve');
  assert.equal(cr.type, 'singleton');
  assert.equal(cr.method, 'PUT');
});

test('classify: old WAF packages are a PATCH collection', () => {
  const c = classify('zones/z/firewall/waf/packages');
  assert.equal(c.type, 'collection');
  assert.equal(c.updateMethod, 'PATCH');
});

test('classify: access policies strip the derived app_count', () => {
  const c = classify('accounts/a/access/policies?per_page=100');
  assert.equal(c.type, 'collection');
  assert.ok(c.strip.includes('app_count'));
});

test('classify: Zero Trust resources', () => {
  assert.equal(classify('accounts/a/access/apps?per_page=100').type, 'collection');
  assert.equal(classify('accounts/a/access/policies?per_page=100').type, 'collection');
  assert.equal(classify('accounts/a/access/service_tokens?per_page=100').type, 'collection');
  assert.equal(classify('accounts/a/cfd_tunnel?is_deleted=false&per_page=100').type, 'collection');
  assert.equal(classify('accounts/a/gateway').type, 'gatewaySettings');
  assert.equal(classify('accounts/a/gateway/rules?per_page=100').type, 'collection');
  assert.equal(classify('accounts/a/devices/settings').type, 'singleton');
  assert.equal(classify('accounts/a/devices/policy/fallback_domains').type, 'listSingleton');
  assert.equal(classify('accounts/a/zt_risk_scoring/settings').type, 'singleton');
  assert.equal(classify('accounts/a/gateway/certificates'), null); // view-only
  assert.equal(classify('accounts/a/access/gateway_ca'), null);   // view-only
  assert.equal(classify('accounts/a/access/keys'), null);         // view-only
});

// ─── Planners ───────────────────────────────────────────────────────────────

test('planSetting: change and no-change', () => {
  const cls = classify('zones/z/settings/security_level');
  const p1 = planEndpoint(cls, { result: { value: 'high' } }, { result: { value: 'medium' } });
  assert.equal(p1.ops.length, 1);
  assert.equal(p1.ops[0].method, 'PATCH');
  assert.deepEqual(p1.ops[0].body, { value: 'high' });

  const p2 = planEndpoint(cls, { result: { value: 'high' } }, { result: { value: 'high' } });
  assert.equal(p2.ops.length, 0);
  assert.equal(p2.unchanged, 1);
});

test('planCollection: create / update / delete / unchanged', () => {
  const cls = classify('zones/z/firewall/lockdowns?per_page=100');
  const snap = [
    { id: 'keep', description: 'same', configurations: [{ target: 'ip', value: '1.1.1.1' }] },
    { id: 'edit', description: 'old' },
    { id: 'new', description: 'added' },
  ];
  const live = [
    { id: 'keep', description: 'same', configurations: [{ target: 'ip', value: '1.1.1.1' }] },
    { id: 'edit', description: 'changed' },
    { id: 'extra', description: 'remove me' },
  ];
  const p = planEndpoint(cls, snap, live);
  const methods = p.ops.map(o => o.method + ':' + o.path.split('/').pop());
  assert.deepEqual(methods.sort(), ['DELETE:extra', 'POST:lockdowns', 'PUT:edit']);
  assert.equal(p.unchanged, 1);
  // PUT body must not contain read-only keys
  const upd = p.ops.find(o => o.method === 'PUT');
  assert.equal(upd.body.id, undefined);
  assert.equal(upd.body.description, 'old');
});

test('planCollection: page-guard refuses truncated lists', () => {
  const cls = classify('zones/z/firewall/lockdowns?per_page=100');
  const many = Array.from({ length: 100 }, (_, i) => ({ id: String(i) }));
  const p = planEndpoint(cls, many, []);
  assert.ok(p.error && /page-size cap/.test(p.error));
});

test('planCollection: firewall rules create as array', () => {
  const cls = classify('zones/z/firewall/rules?per_page=100');
  const snap = [{ id: 'a', expression: 'ip.src eq 1' }, { description: 'new rule', expression: 'ip.src eq 2' }];
  const live = [{ id: 'a', expression: 'ip.src eq 1' }];
  const p = planEndpoint(cls, snap, live);
  const post = p.ops.find(o => o.method === 'POST');
  assert.ok(Array.isArray(post.body));
  assert.equal(post.body.length, 1);
});

test('planCollection: service tokens carry warnings + strip secrets', () => {
  const cls = classify('accounts/a/access/service_tokens?per_page=100');
  const snap = [{ id: 't1', name: 'ci-token', client_secret: 'xxxx', duration: '8760h' }];
  const live = [];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].body.client_secret, undefined);
  assert.ok(p.warnings.length >= 1 && /NEW client secrets/.test(p.warnings[0]));
});

test('planCollection: access apps keep nested policy ids', () => {
  const cls = classify('accounts/a/access/apps?per_page=100');
  const snap = [{
    id: 'app1', name: 'app', domain: 'a.example.com',
    policies: [{ id: 'pol1', name: 'p', decision: 'allow', include: [] }],
  }];
  const live = [{
    id: 'app1', name: 'app', domain: 'b.example.com',
    policies: [{ id: 'pol1', name: 'p', decision: 'allow', include: [] }],
  }];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].body.policies[0].id, 'pol1');
});

test('planDns: content match pairs, update pairs changed, delete extras', () => {
  const cls = classify('zones/z/dns_records?per_page=500');
  const snap = [
    { id: 's1', type: 'A', name: 'a.example.com', content: '1.1.1.1', ttl: 1 },
    { id: 's2', type: 'A', name: 'b.example.com', content: '2.2.2.2', ttl: 300 },
    { id: 's3', type: 'CNAME', name: 'c.example.com', content: 'a.example.com', ttl: 1 },
  ];
  const live = [
    { id: 'l1', type: 'A', name: 'a.example.com', content: '1.1.1.1', ttl: 300 },   // ttl differs → update
    { id: 'l2', type: 'A', name: 'b.example.com', content: '9.9.9.9', ttl: 300 },   // content changed → pair & update
    { id: 'l3', type: 'TXT', name: 'old.example.com', content: 'gone', ttl: 300 }, // not in snapshot → delete
  ];
  const p = planEndpoint(cls, snap, live);
  const updates = p.ops.filter(o => o.method === 'PUT');
  const creates = p.ops.filter(o => o.method === 'POST');
  const deletes = p.ops.filter(o => o.method === 'DELETE');
  assert.equal(updates.length, 2);
  assert.equal(creates.length, 1);   // CNAME c → created
  assert.equal(deletes.length, 1);   // TXT old → deleted
  assert.equal(deletes[0].path.endsWith('/l3'), true);
  // the changed A record was updated in place (not delete+create)
  assert.ok(updates.some(u => u.path.endsWith('/l2') && /2\.2\.2\.2/.test(u.describe)));
});

test('planDns: unchanged when identical', () => {
  const cls = classify('zones/z/dns_records?per_page=500');
  const recs = [{ id: 'r1', type: 'A', name: 'a.example.com', content: '1.1.1.1', ttl: 300, proxied: false }];
  const p = planEndpoint(cls, { result: recs }, { result: recs.map(r => ({ ...r, modified_on: 'x', zone_id: 'z', meta: {} })) });
  assert.equal(p.ops.length, 0);
  assert.equal(p.unchanged, 1);
});

test('planPhaseRuleset: restore preserves ids of live rules, strips read-only', () => {
  const cls = classify('zones/z/rulesets/phases/http_request_transform/entrypoint');
  const snap = {
    id: 'rs1', name: 'transform', rules: [
      { id: 'r1', version: '3', expression: 'true', action: 'rewrite', description: 'keep', last_updated: 't' },
      { id: 'r9', version: '1', expression: 'false', action: 'rewrite', description: 'created' },
    ],
  };
  const live = {
    id: 'rs1', name: 'transform', rules: [
      { id: 'r1', version: '9', expression: 'CHANGED', action: 'rewrite', description: 'keep' },
      { id: 'r2', version: '2', expression: 'x', action: 'rewrite', description: 'to be replaced' },
    ],
  };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  const op = p.ops[0];
  assert.equal(op.method, 'PUT');
  assert.equal(op.body.rules.length, 2);
  assert.equal(op.body.rules[0].id, 'r1');        // existing id preserved
  assert.equal(op.body.rules[0].version, undefined); // read-only stripped
  assert.equal(op.body.rules[1].id, undefined);  // new rule → no stale id
});

test('planPhaseRuleset: account custom rules list form', () => {
  const cls = classify('accounts/a/rulesets?phase=http_request_firewall_custom');
  const snap = [{ id: 'rs', rules: [{ id: 'r1', expression: 'http.host eq 1', action: 'block' }] }];
  const live = [{ id: 'rs', rules: [{ id: 'r2', expression: 'http.host eq 2', action: 'block' }] }];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops[0].path, 'accounts/a/rulesets/phases/http_request_firewall_custom/entrypoint');
});

test('planPhaseRuleset: unchanged when equal modulo read-only keys', () => {
  const cls = classify('zones/z/rulesets/phases/http_request_transform/entrypoint');
  const snap = { id: 'rs', rules: [{ id: 'r1', expression: 'true', action: 'rewrite', version: '1', last_updated: 'a' }] };
  const live = { id: 'rs', rules: [{ id: 'r1', expression: 'true', action: 'rewrite', version: '9', last_updated: 'b' }] };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 0);
  assert.equal(p.unchanged, 1);
});

test('planSingleton: bot management', () => {
  const cls = classify('zones/z/bot_management');
  const snap = { result: { enable_js: true, ai_bots_protection: 'block' } };
  const live = { result: { enable_js: false, ai_bots_protection: 'none' } };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops[0].method, 'PUT');
  assert.deepEqual(p.ops[0].body, { enable_js: true, ai_bots_protection: 'block' });
});

test('planSingleton: devices settings uses PATCH', () => {
  const cls = classify('accounts/a/devices/settings');
  const snap = { result: { default: true } };
  const live = { result: { default: false } };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops[0].method, 'PATCH');
});

test('planSingleton: tiered cache uses POST and strips editable/id', () => {
  const cls = classify('zones/z/cache/tiered_cache_smart_topology_enable');
  const snap = { editable: true, id: 'tiered_cache_smart_topology_enable', value: 'on' };
  const live = { editable: true, id: 'tiered_cache_smart_topology_enable', value: 'off' };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].method, 'POST');
  assert.deepEqual(p.ops[0].body, { value: 'on' });
});

test('planSingleton: cache reserve uses PUT', () => {
  const cls = classify('zones/z/cache/cache_reserve');
  const snap = { editable: true, id: 'cache_reserve', value: 'on' };
  const live = { editable: true, id: 'cache_reserve', value: 'off' };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops[0].method, 'PUT');
  assert.deepEqual(p.ops[0].body, { value: 'on' });
});

test('planCollection: old WAF packages update via PATCH', () => {
  const cls = classify('zones/z/firewall/waf/packages');
  const snap = [{ id: 'p1', name: 'OWASP', sensitivity: 'high', detection_mode: 'traditional', last_updated: 't1' }];
  const live = [{ id: 'p1', name: 'OWASP', sensitivity: 'low', detection_mode: 'traditional', last_updated: 't2' }];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].method, 'PATCH');
  assert.equal(p.ops[0].path, 'zones/z/firewall/waf/packages/p1');
  assert.deepEqual(p.ops[0].body, { name: 'OWASP', sensitivity: 'high', detection_mode: 'traditional' });
});

test('planCollection: access policy app_count churn is not an update', () => {
  const cls = classify('accounts/a/access/policies?per_page=100');
  const snap = [{ id: 'p1', name: 'staff', app_count: 1, include: [{ email: 'a@x.com' }] }];
  const live = [{ id: 'p1', name: 'staff', app_count: 4, include: [{ email: 'a@x.com' }] }];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 0);
  assert.equal(p.unchanged, 1);
});

test('planGatewaySettings: writes to gateway/configuration', () => {
  const cls = classify('accounts/a/gateway');
  const snap = { result: { activity_log_enabled: true, dashboard_url: 'https://x', created_at: 't' } };
  const live = { result: { activity_log_enabled: false, dashboard_url: 'https://y', created_at: 't2' } };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops[0].method, 'PATCH');
  assert.equal(p.ops[0].path, 'accounts/a/gateway/configuration');
  assert.equal(p.ops[0].body.dashboard_url, undefined);
});

test('planManagedHeaders: both shapes tolerated', () => {
  const cls = classify('zones/z/managed_headers');
  const snap = { result: { managed_headers: { enabled: [{ id: 'append_connecting_ip_header' }], disabled: [] } } };
  const live = { result: { managed_headers: { enabled: [], disabled: [{ id: 'append_connecting_ip_header' }] } } };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.deepEqual(p.ops[0].body, { managed_headers: { enabled: ['append_connecting_ip_header'], disabled: [] } });
});

test('planListSingleton: fallback domains full-list PUT', () => {
  const cls = classify('accounts/a/devices/policy/fallback_domains');
  const snap = [{ suffix: 'lan', description: 'local' }, { suffix: 'local', description: '' }];
  const live = [{ suffix: 'lan', description: 'local' }];
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].method, 'PUT');
  assert.equal(p.ops[0].body.length, 2);
});

test('deepDiff: id-less arrays show exactly which items were added/removed', () => {
  const a = { items: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] };
  const b = { items: ['10.0.0.1', '10.0.0.3', '10.0.0.4'] };
  const d = deepDiff(a, b);
  const removed = d.changes.filter(c => c.type === 'removed').map(c => c.before);
  const added = d.changes.filter(c => c.type === 'added').map(c => c.after);
  assert.deepEqual(removed, ['10.0.0.2']);
  assert.deepEqual(added, ['10.0.0.4']);
  assert.ok(d.changes.every(c => c.path === 'items[]'));
});

test('deepDiff: id-less object arrays diff per item with full before/after', () => {
  const a = { origins: [{ name: 'o1', address: '1.1.1.1' }, { name: 'o2', address: '2.2.2.2' }] };
  const b = { origins: [{ name: 'o1', address: '9.9.9.9' }, { name: 'o2', address: '2.2.2.2' }] };
  const d = deepDiff(a, b);
  // o1 changed → shown as removed(old o1) + added(new o1) with full detail
  const removed = d.changes.find(c => c.type === 'removed');
  const added = d.changes.find(c => c.type === 'added');
  assert.equal(removed.before.address, '1.1.1.1');
  assert.equal(added.after.address, '9.9.9.9');
});

test('deepDiff: duplicates and order-only changes in id-less arrays', () => {
  // two of the same value → one removed
  let d = deepDiff({ v: ['a', 'a', 'b'] }, { v: ['a', 'b'] });
  assert.deepEqual(d.changes.filter(c => c.type === 'removed').map(c => c.before), ['a']);
  // reorder only → no changes
  d = deepDiff({ v: ['a', 'b', 'c'] }, { v: ['c', 'b', 'a'] });
  assert.equal(d.changes.length, 0);
});

test('deepDiff: volatile keys inside id-less items do not phantom-diff', () => {
  const a = { origins: [{ name: 'o1', address: '1.1.1.1', healthy: false, failure_reason: 'x' }] };
  const b = { origins: [{ name: 'o1', address: '1.1.1.1', healthy: true, failure_reason: 'y' }] };
  assert.equal(deepDiff(a, b).changes.length, 0);
});

test('stableKey: deterministic across object key order', () => {
  assert.equal(stableKey({ a: 1, b: 2 }), stableKey({ b: 2, a: 1 }));
  assert.notEqual(stableKey({ a: 1 }), stableKey({ a: 2 }));
});

test('classify + plan: gateway lists are item-aware', () => {
  const cls = classify('accounts/a1/gateway/lists?per_page=100');
  assert.equal(cls.type, 'gatewayLists');
  const snap = { result: [
    { id: 'l1', name: 'VIPs', type: 'IP', description: '', items: [{ value: '1.1.1.1' }, { value: '2.2.2.2' }] },
  ] };
  const live = { result: [
    { id: 'l1', name: 'VIPs', type: 'IP', description: '', items: [{ value: '2.2.2.2' }, { value: '3.3.3.3' }] },
  ] };
  const p = planEndpoint(cls, snap, live);
  assert.equal(p.ops.length, 1);
  assert.equal(p.ops[0].method, 'PATCH');
  // append 1.1.1.1 (in snapshot, not live), remove 3.3.3.3 (in live, not snapshot)
  assert.deepEqual(p.ops[0].body.append, [{ value: '1.1.1.1' }]);
  assert.deepEqual(p.ops[0].body.remove, ['3.3.3.3']);
});

test('plan gateway lists: metadata change → PUT, item description change → append+remove', () => {
  const cls = classify('accounts/a1/gateway/lists');
  const snap = { result: [
    { id: 'l1', name: 'NewName', type: 'SERIAL', description: 'd', items: [{ value: 'S1', description: 'old desc' }] },
  ] };
  const live = { result: [
    { id: 'l1', name: 'OldName', type: 'SERIAL', description: 'd', items: [{ value: 'S1', description: 'new desc' }] },
  ] };
  const p = planEndpoint(cls, snap, live);
  const put = p.ops.find(o => o.method === 'PUT');
  const patch = p.ops.find(o => o.method === 'PATCH');
  assert.ok(put, 'list metadata PUT expected');
  assert.equal(put.body.name, 'NewName');
  assert.ok(!('items' in put.body) && !('count' in put.body), 'PUT body must not include items/count');
  assert.ok(patch, 'items PATCH expected');
  assert.deepEqual(patch.body.append, [{ value: 'S1', description: 'old desc' }]);
  assert.deepEqual(patch.body.remove, ['S1']);
});

test('plan gateway lists: new list with items → POST create + PATCH append', () => {
  const cls = classify('accounts/a1/gateway/lists');
  const snap = { result: [
    { id: 'l9', name: 'Fresh', type: 'IP', items: [{ value: '5.5.5.5' }] },
  ] };
  const live = { result: [] };
  const p = planEndpoint(cls, snap, live);
  const post = p.ops.find(o => o.method === 'POST');
  const patch = p.ops.find(o => o.method === 'PATCH');
  assert.ok(post, 'POST create expected');
  assert.equal(post.body.name, 'Fresh');
  assert.ok(patch, 'PATCH append for new list items expected');
  assert.deepEqual(patch.body.append, [{ value: '5.5.5.5' }]);
});

test('plan gateway lists: identical → unchanged', () => {
  const cls = classify('accounts/a1/gateway/lists');
  const list = { id: 'l1', name: 'N', type: 'IP', items: [{ value: '1.1.1.1' }] };
  const p = planEndpoint(cls, { result: [list] }, { result: [structuredClone(list)] });
  assert.equal(p.ops.length, 0);
  assert.equal(p.unchanged, 1);
});

// ─── Reference catalog (settings reference page data) ───────────────────────

test('reference: every catalog endpoint has a description', () => {
  for (const c of CATEGORIES) {
    for (const ep of c.endpoints) {
      assert.ok(ep.desc && ep.desc.length >= 10, `${c.key}.${ep.name} is missing a description`);
    }
  }
});

test('reference: every RESTORE_NOTES entry matches a catalog endpoint', () => {
  const names = new Set(CATEGORIES.flatMap(c => c.endpoints.map(ep => ep.name)));
  for (const key of Object.keys(RESTORE_NOTES)) {
    assert.ok(names.has(key), `RESTORE_NOTES key "${key}" is not a catalog endpoint`);
  }
});

test('reference: every endpoint path template renders for the reference page', () => {
  for (const c of CATEGORIES) {
    for (const ep of c.endpoints) {
      const rendered = ep.path(':zone', ':account');
      assert.ok(typeof rendered === 'string' && rendered.includes('/:'), `${c.key}.${ep.name} path did not render`);
    }
  }
});

test('reference: restorability classification spot checks', () => {
  const byName = (n) => CATEGORIES.flatMap(c => c.endpoints.map(ep => ({ cat: c, ep }))).find(x => x.ep.name === n);
  const restorable = (n) => {
    const { ep } = byName(n);
    const cls = classify(ep.path(':zone', ':account'));
    return !!(cls && cls.type !== 'view_only');
  };
  // restorable settings
  for (const n of ['dns_records', 'firewall_rules', 'gateway_lists', 'cache_rules', 'tiered_cache', 'cache_reserve',
    'waf_managed_rules', 'access_policies', 'waf_custom_rules_acct']) {
    assert.ok(restorable(n), n + ' should be restorable');
  }
  // view-only settings
  for (const n of ['custom_certificates', 'custom_hostnames', 'dnssec', 'gateway_certificates', 'access_keys', 'dlp_profiles', 'rulesets']) {
    assert.ok(!restorable(n), n + ' should be view-only');
  }
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
