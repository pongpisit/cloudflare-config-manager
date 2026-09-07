// ─── Shared Cloudflare API client ───────────────────────────────────────────

const API_BASE = 'https://api.cloudflare.com/client/v4';

export function normalizeToken(raw) {
  if (!raw) return null;
  return raw.startsWith('Bearer ') ? raw : `Bearer ${raw}`;
}

// Perform a Cloudflare API call. Returns { status, ok, json }.
export async function cf(method, path, token, body) {
  const res = await fetch(`${API_BASE}/${path}`, {
    method,
    headers: {
      Authorization: token,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON body */ }
  return { status: res.status, ok: res.ok, json };
}

// Extract a list payload from a CF API response body, tolerating both
// { result: [...] } envelopes and already-unwrapped arrays.
export function toItems(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.result)) return data.result;
  return [];
}

// Fetch a set of config endpoints in parallel. Silently skips endpoints the
// token cannot access. tasks: [{ catKey, name, path }]
// Gateway lists are enriched with their actual items (the collection endpoint
// only returns a count) so diffs and restores work at item level.
export async function fetchEndpoints(token, tasks) {
  const fetchOne = async ({ catKey, name, path }) => {
    try {
      const { status, ok, json } = await cf('GET', path, token);
      // Permission denied / not found / feature not available → skip silently
      if (!ok || (json && json.success === false)) {
        // Keep the original behavior: body-level permission errors → skipped
        const bodyPermError = json?.errors?.some(e =>
          e.code === 10000 || e.code === 9109 || e.code === 7003 ||
          (e.message && /permission|not allowed|unauthorized|forbidden/i.test(e.message)));
        const status_ = (status === 401 || status === 403 || status === 404 || bodyPermError) ? 'skipped' : 'error';
        return { catKey, name, path, status: status_, data: null, http: status };
      }
      let data = json.result ?? json;
      if (name === 'gateway_lists' && Array.isArray(data)) {
        const accountId = (path.match(/^accounts\/([^/]+)\//) || [])[1];
        if (accountId) data = await enrichGatewayLists(token, accountId, data);
      }
      return { catKey, name, path, status: 'ok', data, http: status };
    } catch {
      return { catKey, name, path, status: 'error', data: null };
    }
  };
  return Promise.all(tasks.map(fetchOne));
}

// Embed the items of every Gateway list (normalized to {value, description})
// so versioning, diffs and restores see exactly which items exist. The
// collection endpoint only returns a derived count.
export async function enrichGatewayLists(token, accountId, lists) {
  await Promise.all(lists.slice(0, 50).map(async (list) => {
    try {
      const r = await cf('GET', `accounts/${accountId}/gateway/lists/${list.id}/items?per_page=500`, token);
      if (r.ok && r.json?.success && Array.isArray(r.json.result)) {
        list.items = r.json.result
          .map(i => (i && typeof i === 'object'
            ? { value: i.value, ...(i.description ? { description: i.description } : {}) }
            : { value: i }))
          .filter(i => i.value !== undefined && i.value !== null);
      }
    } catch { /* items unavailable — list stays without items */ }
  }));
  return lists;
}

// Assemble the standard snapshot output structure from fetchEndpoints results.
// scope='account' → account-level configuration (Cloudflare One, account WAF,
// Magic WAN…): zone_id is null and zone_id-keyed versioning treats the
// account id as the versioning key.
export function assembleConfig(results, { zoneId, accountId, selectedCats, scope = 'zone' }) {
  const output = {};
  let totalFetched = 0, totalSkipped = 0;
  const metaEndpoints = [];

  for (const r of results) {
    if (r.status === 'ok') totalFetched++; else totalSkipped++;
    metaEndpoints.push({ catKey: r.catKey, name: r.name, path: r.path, status: r.status });
    if (r.status === 'ok') {
      if (!output[r.catKey]) output[r.catKey] = {};
      output[r.catKey][r.name] = r.data;
    }
  }

  output._meta = {
    timestamp: new Date().toISOString(),
    zone_id: scope === 'account' ? null : zoneId,
    zone_name: scope === 'account' ? 'Account — Cloudflare One' : undefined,
    account_id: accountId || null,
    scope,
    categories_requested: selectedCats,
    total_fetched: totalFetched,
    total_skipped: totalSkipped,
    fetched_endpoints: metaEndpoints,
  };
  return output;
}

// Fetch recent account audit-log entries after `sinceIso` (ISO 8601).
// Used by the scheduled check to detect whether anything changed in
// Cloudflare since the last poll before running the full drift comparison.
export async function fetchAuditLogs(token, accountId, sinceIso, perPage = 50) {
  const { status, ok, json } = await cf('GET',
    `accounts/${accountId}/audit_logs?per_page=${perPage}${sinceIso ? `&since=${encodeURIComponent(sinceIso)}` : ''}`,
    token);
  if (!ok || !json || json.success === false) {
    const err = new Error(`audit log fetch failed (${status})`);
    err.status = status;
    throw err;
  }
  const entries = (json.result || []).filter(e => !sinceIso || !e.when || new Date(e.when) > new Date(sinceIso));
  return entries;
}
// Build the task list for a fetch from selected categories, filtered by
// PRODUCT (never mixed):
//   'appsec' — the AppSec product: zone-level WAF/DDoS/Bot/API Shield + TLS/
//              CDN/DNS context PLUS account-level WAF (custom rules, account
//              IP access rules — included when an accountId is available)
//   'one'    — the Cloudflare One product: pure Zero Trust (Access, Gateway,
//              tunnels, devices, DLP), account-level only
export function buildTasks(zoneId, accountId, selectedCats, CATEGORIES, product = 'appsec') {
  const tasks = [];
  for (const cat of CATEGORIES) {
    if (!selectedCats.includes(cat.key)) continue;
    for (const ep of cat.endpoints) {
      if ((ep.product || 'appsec') !== product) continue;
      if (ep.accountRequired && !accountId) continue;
      tasks.push({ catKey: cat.key, name: ep.name, path: ep.path(zoneId, accountId) });
    }
  }
  return tasks;
}
