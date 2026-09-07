// UI-driven restore E2E — runs the REAL client script from src/ui.js against a
// local wrangler dev worker with REAL Cloudflare API calls.
//
// Flow: fetch → save v1 → real config change → check (detects) → restore modal
// (scope → review → result) → dry-run → execute → verify restoration.
//
// Usage:
//   npx wrangler dev --port 8787   (in another terminal)
//   CF_API_TOKEN=... ZONE_ID=... node test/ui-restore.e2e.mjs

import { readFileSync } from 'node:fs';

const BASE = process.env.BASE_URL || 'http://localhost:8787';
const CF_TOKEN = process.env.CF_API_TOKEN;
const ZONE_ID = process.env.ZONE_ID;
const ACCT = process.env.ACCOUNT_ID;

if (!CF_TOKEN) { console.error('CF_API_TOKEN env var required'); process.exit(1); }
if (!ZONE_ID) { console.error('ZONE_ID env var required (a test zone you control)'); process.exit(1); }
if (!ACCT) { console.error('ACCOUNT_ID env var required (the zone\'s account)'); process.exit(1); }

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('  ✓ ' + name); }
  else { failed++; console.error('  ✗ ' + name); }
}

// ── Minimal DOM shim (only what the client script uses) ────────────────────
const registry = [];
function makeEl(tag = 'div') {
  const e = {
    tagName: tag, children: [], options: [], selectedIndex: 0,
    className: '', value: '', textContent: '', innerHTML: '',
    disabled: false, title: '', dataset: {}, style: {},
    _classes: new Set(),
    appendChild(c) {
      e.children.push(c);
      if (c.tagName === 'option') { e.options.push(c); if (!e._valueSet) { e.value = c.value; e._valueSet = true; } }
      if (e.tagName === 'tbody') e.innerHTML += (c.innerHTML || '');
      return c;
    },
    remove() {}, scrollIntoView() {}, click() {},
    addEventListener() {},
    querySelector() { return makeEl('input'); },
    querySelectorAll() { return []; },
  };
  e.classList = {
    add: (...cs) => cs.forEach(c => e._classes.add(c)),
    remove: (...cs) => cs.forEach(c => e._classes.delete(c)),
    toggle: (c, force) => { const on = force !== undefined ? force : !e._classes.has(c); on ? e._classes.add(c) : e._classes.delete(c); return on; },
    contains: (c) => e._classes.has(c),
  };
  registry.push(e);
  return e;
}

const elements = {};
const el = (id) => elements[id] || (elements[id] = makeEl(id.endsWith('-tbody') ? 'tbody' : 'div'));

globalThis.document = {
  getElementById: el,
  createElement: (t) => makeEl(t),
  body: makeEl('body'),
  addEventListener: () => {},
  querySelectorAll: (sel) => {
    if (sel === '.cat-card.selected') {
      return registry.filter(e => {
        const cs = String(e.className).split(/\s+/);
        return cs.includes('cat-card') && cs.includes('selected');
      });
    }
    if (sel === '.modal-cat input:checked') {
      const html = String(el('modal-body').innerHTML);
      return [...html.matchAll(/<input type="checkbox" checked value="([^"]+)"/g)].map(m => ({ value: m[1], checked: true }));
    }
    return [];
  },
};
globalThis.window = { scrollTo: () => {} };
try { globalThis.navigator = {}; } catch { /* node defines navigator as getter-only; unused paths only */ }
// localStorage shim (session persistence)
const lsStore = {};
globalThis.localStorage = {
  getItem: (k) => (k in lsStore ? lsStore[k] : null),
  setItem: (k, v) => { lsStore[k] = String(v); },
  removeItem: (k) => { delete lsStore[k]; },
};
globalThis.location = { reload: () => {} };
let confirms = 0;
globalThis.alert = (m) => { /* console.log('   [alert]', String(m).slice(0, 100)); */ };
globalThis.confirm = () => { confirms++; return true; };
globalThis.prompt = (msg, def) => def || 'ui-test';
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts = {}) => realFetch(String(url).startsWith('http') ? String(url) : BASE + String(url), opts);

// ── Load and run the real client script ─────────────────────────────────────
const { UI_HTML } = await import('../src/ui.js');
const code = UI_HTML.match(/<script>([\s\S]*)<\/script>/)[1];
const expose = `;window.__ui = { loadZones, fetchConfigs, saveVersion, checkChanges, loadVersions, loadOverview, rollbackVersion, doRollback, getVersions: (s) => SCOPES[s].state.versions };`;
new Function(code + expose)();
await new Promise(r => setTimeout(r, 500)); // let init() settle

const ui = globalThis.window.__ui;

async function cf(method, path, body) {
  const res = await realFetch(`https://api.cloudflare.com/client/v4/${path}`, {
    method,
    headers: { Authorization: `Bearer ${CF_TOKEN}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

// ── The flow ────────────────────────────────────────────────────────────────
console.log('── setup: load zones, select target');
el('api-token').value = CF_TOKEN;
el('account-id').value = ACCT;
await ui.loadZones();
const sel = el('zone-select');
const idx = sel.options.findIndex(o => o.value === ZONE_ID);
check('zones loaded', sel.options.length >= 1);
sel.selectedIndex = idx >= 0 ? idx : 0;
sel.value = ZONE_ID;
console.log('   zone:', sel.options[sel.selectedIndex].textContent);

console.log('── step 1: fetch configs + save a version via the UI');
await cf('PATCH', `zones/${ZONE_ID}/settings/browser_check`, { value: 'on' }); // deterministic start state
await ui.loadZones();
await ui.loadOverview();
check('session saved to localStorage', !!lsStore['cf_config_session'] && JSON.parse(lsStore['cf_config_session']).token === CF_TOKEN);
check('targets overview rendered', String(el('overview-tbody').innerHTML).includes(ZONE_ID));
await ui.loadVersions('zone');
const before = (ui.getVersions('zone')[0] || {}).version || 0;
await ui.fetchConfigs('zone');
await ui.saveVersion('zone');
await ui.loadVersions('zone');
const after = (ui.getVersions('zone')[0] || {}).version || 0;
check('version recorded (or already current)', after >= before);
// whether a new version was created or it was a no-change save, the latest
// version's state equals the live state we just captured — that's our target
const target = ui.getVersions('zone')[0];
check('restore target exists', !!target);

console.log('── step 2: real config change (browser_check on → off)');
await cf('PATCH', `zones/${ZONE_ID}/settings/browser_check`, { value: 'off' });
const liveOff = await cf('GET', `zones/${ZONE_ID}/settings/browser_check`);
check('live browser_check = off', liveOff.result.value === 'off');

console.log('── step 2b: re-fetch shows the drift banner');
await ui.fetchConfigs('zone');
const bannerHtml = String(el('zone-drift-banner').innerHTML);
check('drift banner warns of difference', bannerHtml.includes('differs from v') && bannerHtml.includes('Save as new version'));
check('results marked unsaved', String(el('zone-results-info').innerHTML).includes('not saved') || (el('zone-results-info').textContent || '').includes('not saved'));

console.log('── step 3: UI check detects the change → new delta version');
await ui.checkChanges('zone');
await ui.loadVersions('zone');
const latest = ui.getVersions('zone')[0];
// recorded as a delta, or compacted to full when the delta is large relative
// to the base (e.g. the general.settings bulk endpoint is in the change set)
check('new version recorded', latest.version > after);
// with the policy scope, browser_check lives only in appsec.browser_check
// (the bulk zone settings endpoint is out of scope) → exactly 1 endpoint
check('change summary shows 1 endpoint', latest.change_summary.endpoints === 1);

console.log('── step 4: restore modal (scope step)');
ui.rollbackVersion(target.id);
const modalHtml = String(el('modal-body').innerHTML);
check('modal shows stepped flow', modalHtml.includes('rb-step-1') && modalHtml.includes('rb-step-2') && modalHtml.includes('rb-step-3'));
// the browser parses the modal HTML into real buttons — mirror that so the
// button-gating logic is observable on the shim elements
const execBtnHtml = (modalHtml.match(/<button[^>]*id="rb-execute-btn"[^>]*>/) || [''])[0];
check('execute disabled before preview (in markup)', /\bdisabled\b/.test(execBtnHtml));
if (/\bdisabled\b/.test(execBtnHtml)) el('rb-execute-btn').disabled = true;

console.log('── step 5: preview (review step)');
await ui.doRollback(target.id, true);
const dryHtml = String(el('rollback-result').innerHTML);
check('state diff rendered', dryHtml.includes('browser_check') && dryHtml.includes('Changes that will be applied'));
check('planned op shown', dryHtml.includes('browser_check:'));
check('execute unlocked after review', el('rb-execute-btn').disabled === false);

console.log('── step 6: execute restore (result step)');
const confirmsBefore = confirms;
await ui.doRollback(target.id, false);
const execHtml = String(el('rollback-result').innerHTML);
check('confirm dialog used', confirms > confirmsBefore);
check('restore summary rendered', execHtml.includes('Restore summary'));
check('safety snapshot shown', execHtml.includes('Safety snapshot'));
check('restore bumps version shown', execHtml.includes('restored state recorded as v'));
check('verification shown', execHtml.includes('verified'));

console.log('── step 7: verify real Cloudflare state restored');
const liveAfter = await cf('GET', `zones/${ZONE_ID}/settings/browser_check`);
check('live browser_check = on (restored)', liveAfter.result.value === 'on');

await ui.loadVersions('zone');
const vs = ui.getVersions('zone');
check('post-restore version recorded (trigger rollback)', vs.some(v => v.trigger_type === 'rollback'));
console.log('   version history:', vs.map(v => 'v' + v.version + ':' + (v.named ? 'named' : v.kind) + '/' + v.trigger_type).join('  '));

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
