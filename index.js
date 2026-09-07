// ─── Cloudflare Configuration Manager ────────────────────────────────────────
// Fetches Cloudflare configurations, stores immutable version snapshots
// (D1 + R2), records an append-only audit trail, and rolls zones/accounts back
// to any previous policy version — including Zero Trust resources.

import { CATEGORIES } from './src/categories.js';
import { normalizeToken, fetchEndpoints, buildTasks, assembleConfig } from './src/cfapi.js';
import { getActor } from './src/auth.js';
import { writeAudit, listTrackedZones, recordTrackedZoneCheck, httpError, getAuditWatermark, setAuditWatermark } from './src/db.js';
import { deepDiff, summarizeChanges } from './src/diff.js';
import { UI_HTML } from './src/ui.js';
import { attributionLabel } from './src/versioning.js';
import { fetchAuditLogs } from './src/cfapi.js';
import { classify, RESTORE_NOTES } from './src/rollback.js';
import {
  handleSnapshotCreate, handleSnapshotList, handleSnapshotGet, handleSnapshotDelete,
  handleSnapshotDiff, handleRollback, handleAuditQuery, handleVersionCheck,
  handleVersionChanges, checkAndVersionZone, handleTrackedZones,
} from './src/snapshots.js';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

// Wrap a handler so thrown httpErrors become clean JSON responses.
const wrap = (fn) => async (...args) => {
  try {
    return await fn(...args);
  } catch (e) {
    if (e && e.status) return json({ error: e.message }, e.status);
    console.error('Unhandled error:', e);
    return json({ error: 'Internal error' }, 500);
  }
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── CORS preflight ──
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization, Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // ── UI ──
    if (url.pathname === '/' && (request.method === 'GET' || request.method === 'HEAD')) {
      return new Response(request.method === 'HEAD' ? null : UI_HTML, {
        headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' },
      });
    }

    // ── Category metadata (public: no auth, no CF token) ──
    // Includes the full Reference catalog: per-endpoint description, path
    // template, scope, product and restorability (from the rollback engine's
    // classification) so the UI Reference page renders from one source of truth.
    if (url.pathname === '/api/categories') {
      return json(CATEGORIES.map(c => ({
        key: c.key,
        label: c.label,
        scopes: [...new Set(c.endpoints.map(ep => ep.scope || 'zone'))],
        product: [...new Set(c.endpoints.map(ep => ep.product || 'appsec'))][0] || 'appsec',
        endpoints: c.endpoints.map(ep => {
          const cls = classify(ep.path(':zone', ':account'));
          return {
            name: ep.name,
            desc: ep.desc || '',
            path: ep.path(':zone', ':account').split('?')[0],
            scope: ep.scope || 'zone',
            product: ep.product || 'appsec',
            restorable: !!(cls && cls.type !== 'view_only'),
            restore_kind: cls ? (cls.type === 'view_only' ? null : cls.type) : null,
            restore_note: RESTORE_NOTES[ep.name] || (cls && cls.warnCreate) || null,
          };
        }),
      })));
    }

    // ── Authentication (Cloudflare Access) ──
    const actor = await getActor(env, request);
    if (!actor) {
      await writeAudit(env, {
        actor: 'unknown', action: 'auth.denied', outcome: 'denied',
        details: { path: url.pathname, method: request.method },
      }).catch(() => {});
      return json({ error: 'Authentication required — sign in via Cloudflare Access.' }, 401);
    }

    // ── Routes that need neither the CF token nor a zone ──
    if (url.pathname === '/api/whoami' && request.method === 'GET') {
      return json({
        actor: actor.actor,
        authenticated: actor.authenticated,
        access_configured: actor.access_configured ?? true,
      });
    }

    if (url.pathname === '/api/audit' && request.method === 'GET') {
      return wrap(handleAuditQuery)(env, url);
    }

    // Targets overview for the dashboard (tracked zones + drift status).
    if (url.pathname === '/api/tracked-zones' && request.method === 'GET') {
      return wrap(handleTrackedZones)(env);
    }

    if (url.pathname === '/api/diff' && request.method === 'POST') {
      return wrap(async () => {
        const body = await request.json().catch(() => null);
        if (!body || body.a === undefined || body.b === undefined) {
          throw httpError(400, 'Both "a" and "b" payloads are required');
        }
        const { changes, truncated } = deepDiff(body.a, body.b, { maxChanges: 500 });
        return json({
          changes,
          truncated,
          summary: summarizeChanges(changes),
          skipped: [],
        });
      })();
    }

    // ── Snapshots & rollback ──
    if (url.pathname === '/api/snapshots') {
      if (request.method === 'POST') return wrap(handleSnapshotCreate)(env, request, actor);
      if (request.method === 'GET') return wrap(handleSnapshotList)(env, url);
      return json({ error: 'Method not allowed' }, 405);
    }

    let m;
    if ((m = url.pathname.match(/^\/api\/snapshots\/([^/]+)$/))) {
      const id = m[1];
      if (request.method === 'GET') return wrap(handleSnapshotGet)(env, actor, id);
      if (request.method === 'DELETE') return wrap(handleSnapshotDelete)(env, url, actor, id);
      return json({ error: 'Method not allowed' }, 405);
    }

    if ((m = url.pathname.match(/^\/api\/snapshots\/([^/]+)\/diff$/)) && request.method === 'GET') {
      return wrap(handleSnapshotDiff)(env, request, actor, m[1], url);
    }

    // ── Change detection & version detail ──
    if (url.pathname === '/api/versions/check' && request.method === 'POST') {
      return wrap(handleVersionCheck)(env, request, actor);
    }

    if ((m = url.pathname.match(/^\/api\/versions\/([^/]+)\/changes$/)) && request.method === 'GET') {
      return wrap(handleVersionChanges)(env, actor, m[1]);
    }

    if (url.pathname === '/api/rollback' && request.method === 'POST') {
      return wrap(handleRollback)(env, request, actor);
    }

    // ── Cloudflare API proxy routes (require the user's CF token) ──
    const apiToken = normalizeToken(request.headers.get('Authorization'));
    if (!apiToken && url.pathname.startsWith('/api/')) {
      return json({ error: 'Missing Authorization header' }, 401);
    }

    if (url.pathname === '/api/zones' && request.method === 'GET') {
      const res = await fetch('https://api.cloudflare.com/client/v4/zones?per_page=200', {
        headers: { Authorization: apiToken },
      });
      return new Response(res.body, {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // Account discovery — lets the UI auto-fill the Account ID (enables the
    // Cloudflare One target) instead of asking the user to find it.
    if (url.pathname === '/api/accounts' && request.method === 'GET') {
      const res = await fetch('https://api.cloudflare.com/client/v4/accounts', {
        headers: { Authorization: apiToken },
      });
      return new Response(res.body, {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // ── Cloudflare One (Zero Trust) — account-level, product-pure ──
    if (url.pathname.startsWith('/api/account-configs/') && request.method === 'GET') {
      const accountId = url.pathname.replace('/api/account-configs/', '').split('/')[0];
      if (!accountId) return json({ error: 'accountId required' }, 400);
      const allCats = CATEGORIES.map(c => c.key);
      const tasks = buildTasks(null, accountId, allCats, CATEGORIES, 'one');
      if (!tasks.length) return json({ error: 'No Zero Trust endpoints available' }, 400);
      const results = await fetchEndpoints(apiToken, tasks);
      const contributingCats = [...new Set(tasks.map(t => t.catKey))];
      const output = assembleConfig(results, {
        zoneId: null,
        accountId,
        selectedCats: contributingCats,
        scope: 'account',
      });
      return json(output);
    }

    if (url.pathname.startsWith('/api/configs/') && request.method === 'GET') {
      const zoneId = url.pathname.replace('/api/configs/', '').split('/')[0];
      const params = url.searchParams;
      const selectedCats = params.get('cats')
        ? params.get('cats').split(',')
        : CATEGORIES.map(c => c.key);
      const accountId = params.get('accountId') || '';

      // AppSec product: zone-level WAF/DDoS/Bot/API Shield + TLS/CDN/DNS, PLUS
      // account-level WAF (custom rules, IP access rules) when an account id
      // is available. Zero Trust is never included — it has its own page.
      const tasks = buildTasks(zoneId, accountId, selectedCats, CATEGORIES, 'appsec');
      const results = await fetchEndpoints(apiToken, tasks);
      const output = assembleConfig(results, { zoneId, accountId, selectedCats, scope: 'zone' });
      return json(output);
    }

    return new Response('Not Found', { status: 404 });
  },

  // ── Scheduled change detection (cron, every 5 minutes) ──
  // Requires the CF_API_TOKEN secret (read-only) — otherwise the run is
  // skipped. Each run first polls Cloudflare's audit log (1 API call):
  //   • no new audit entries → nothing changed in Cloudflare, the heavy
  //     comparison is skipped (tracked zones are still marked checked)
  //   • new audit entries     → the full drift comparison runs for every
  //     tracked target, and any drift is recorded as a new delta version
  //     labeled with who made the change (from the audit entries)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduledCheck(env));
  },
};

async function runScheduledCheck(env) {
  const raw = env.CF_API_TOKEN;
  if (!raw) {
    console.log('[scheduled] CF_API_TOKEN secret not set — skipping change detection');
    return;
  }
  const token = raw.startsWith('Bearer ') ? raw : `Bearer ${raw}`;

  let zones = [];
  try {
    zones = await listTrackedZones(env);
  } catch (e) {
    console.error('[scheduled] could not list tracked zones:', e?.message || e);
    return;
  }
  if (!zones.length) return;

  // ── Audit-log pre-check: did anything change in Cloudflare since the last poll? ──
  const accountId = zones.find(z => z.account_id)?.account_id;
  let audit = null;
  if (accountId) {
    try {
      const previous = await getAuditWatermark(env, accountId);
      const since = previous || new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const entries = await fetchAuditLogs(token, accountId, since);
      let watermark = since;
      for (const e of entries) {
        if (e.when && new Date(e.when) > new Date(watermark)) watermark = e.when;
      }
      await setAuditWatermark(env, accountId, watermark);
      audit = { count: entries.length, entries };
    } catch (e) {
      console.error('[scheduled] audit log poll failed — falling back to full check:', e?.message || e);
    }
  }

  if (audit && audit.count === 0) {
    // Nothing changed in Cloudflare — skip the comparison, keep the dashboard fresh
    for (const z of zones) {
      await recordTrackedZoneCheck(env, z.zone_id, 'no_change (audit)', z.last_version);
    }
    console.log(`[scheduled] audit poll: no Cloudflare activity — skipped comparison for ${zones.length} target(s)`);
    return;
  }

  const label = audit && audit.count > 0 ? attributionLabel(audit.entries) : null;
  console.log(`[scheduled] ${audit ? `${audit.count} new audit entr${audit.count === 1 ? 'y' : 'ies'}` : 'audit poll unavailable'} — running drift check for ${zones.length} target(s)`);

  for (const z of zones) {
    try {
      const result = await checkAndVersionZone(env, {
        token, zoneId: z.zone_id, trigger: 'scheduled', actor: 'scheduled', label,
      });
      console.log(`[scheduled] ${z.zone_id}: ${result.created ? `changed → v${result.version}` : (result.would_create ? 'drift (preview)' : 'no change')}`);
    } catch (e) {
      console.error(`[scheduled] check failed for ${z.zone_id}:`, e?.message || e);
      try {
        await recordTrackedZoneCheck(env, z.zone_id, 'error: ' + String(e?.message || e).slice(0, 200), z.last_version);
      } catch { /* zone row may not exist yet */ }
    }
  }
}
