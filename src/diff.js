// ─── Deep JSON diff ──────────────────────────────────────────────────────────
// Used for snapshot↔snapshot and snapshot↔live diffs and rollback verification.
// - Ignores volatile timestamp keys so re-fetches don't produce noise.
// - Arrays of objects with stable `id` fields are diffed per-item.
// - Missing keys on either side become added/removed changes.

const IGNORE_KEYS = new Set([
  'modified_on', 'modified_at', 'last_updated', 'etag', 'updated_at',
  // fetch-metadata timestamps that change on every read (e.g. API Shield
  // schemas, tunnel run times, service token usage)
  'timestamp', 'run_at', 'last_seen_at',
  // runtime state, not configuration: load balancer origin health details and
  // database file sizes change on every fetch / with usage
  'healthy', 'failure_reason', 'file_size',
  // caller-dependent metadata: zones/:id "permissions" lists what the calling
  // token may do — it churns whenever a different/updated token fetches
  'permissions',
  // derived totals (e.g. gateway list item counts — items are diffed directly)
  'count',
]);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function truncateStr(s, n = 400) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + `…(+${s.length - n} chars)` : s;
}

// Deterministic JSON key with sorted object keys (for multiset comparisons).
export function stableKey(v) {
  if (v === null || typeof v !== 'object') return v === undefined ? 'undefined' : JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableKey).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stableKey(v[k])).join(',') + '}';
}

export function deepDiff(a, b, opts = {}) {
  const maxChanges = opts.maxChanges ?? 500;
  const extraIgnore = opts.ignoreKeys ? new Set(opts.ignoreKeys) : null;
  const changes = [];
  let truncated = false;

  const add = (change) => {
    if (changes.length >= maxChanges) { truncated = true; return; }
    changes.push(change);
  };

  const walk = (x, y, path) => {
    if (x === y) return;
    if (x === undefined) return add({ path: path || 'root', type: 'added', after: y });
    if (y === undefined) return add({ path: path || 'root', type: 'removed', before: x });
    if (isObj(x) && isObj(y)) {
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      for (const k of keys) {
        if (IGNORE_KEYS.has(k) || (extraIgnore && extraIgnore.has(k))) continue;
        walk(x[k], y[k], path ? `${path}.${k}` : k);
      }
      return;
    }
    if (Array.isArray(x) && Array.isArray(y)) return walkArray(x, y, path);
    add({ path: path || 'root', type: 'changed', before: x, after: y });
  };

  const idMap = (arr) => {
    if (!arr.length || !arr.every(i => isObj(i) && i.id !== undefined)) return null;
    const m = new Map();
    for (const item of arr) m.set(String(item.id), item);
    return m;
  };

  // Multiset bucket for id-less array diffing: key = stable JSON of the
  // volatile-stripped element (object keys sorted), value = count + raw.
  const countMap = (arr) => {
    const m = new Map();
    for (const v of arr) {
      const key = stableKey(stripIgnored(v));
      const entry = m.get(key) || { n: 0, raw: v };
      entry.n++;
      m.set(key, entry);
    }
    return m;
  };

  // Deep copy with volatile keys removed (used for id-less array comparison).
  const stripIgnored = (v) => {
    if (Array.isArray(v)) return v.map(stripIgnored);
    if (isObj(v)) {
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        if (IGNORE_KEYS.has(k) || (extraIgnore && extraIgnore.has(k))) continue;
        out[k] = stripIgnored(val);
      }
      return out;
    }
    return v;
  };

  const walkArray = (x, y, path) => {
    const xm = idMap(x), ym = idMap(y);
    // Id-based diff when both sides are id-keyed, or when one side is empty
    // (every item on the other side was added/removed).
    if ((xm && (ym || y.length === 0)) || (ym && x.length === 0)) {
      for (const [id, xv] of xm || []) {
        const yv = ym ? ym.get(id) : undefined;
        if (yv === undefined) add({ path: `${path}[id=${id}]`, type: 'removed', before: xv });
        else walk(xv, yv, `${path}[id=${id}]`);
      }
      for (const [id, yv] of ym || []) {
        if (!xm || !xm.has(id)) add({ path: `${path}[id=${id}]`, type: 'added', after: yv });
      }
      return;
    }
    // Id-less arrays → multiset diff showing EXACTLY which items were added
    // or removed (volatile keys stripped from the comparison key). Order-only
    // differences are not changes.
    const xMap = countMap(x), yMap = countMap(y);
    for (const [key, entry] of xMap) {
      const yn = yMap.get(key)?.n ?? 0;
      for (let i = 0; i < entry.n - yn; i++) {
        add({ path: `${path}[]`, type: 'removed', before: entry.raw });
      }
    }
    for (const [key, entry] of yMap) {
      const xn = xMap.get(key)?.n ?? 0;
      for (let i = 0; i < entry.n - xn; i++) {
        add({ path: `${path}[]`, type: 'added', after: entry.raw });
      }
    }
  };

  walk(a, b, '');
  return { changes, truncated };
}

export function summarizeChanges(changes) {
  const summary = { added: 0, removed: 0, changed: 0 };
  for (const c of changes) {
    if (summary[c.type] !== undefined) summary[c.type]++;
  }
  return summary;
}

// Compare two config payloads ({category: {endpoint: data}}, with _meta).
// `skip` is a Set of "cat|name" endpoint keys to exclude (e.g. endpoints that
// could not be fetched live and would produce misleading wholesale diffs).
export function diffConfigs(a, b, { skip = new Set(), maxChanges = 500, volatileKeys = {} } = {}) {
  const changes = [];
  let truncated = false;
  const skipped = [];

  const cats = new Set([
    ...Object.keys(a || {}), ...Object.keys(b || {})
  ].filter(k => k !== '_meta'));

  for (const cat of cats) {
    const endpoints = new Set([
      ...Object.keys((a || {})[cat] || {}),
      ...Object.keys((b || {})[cat] || {})
    ]);
    for (const ep of endpoints) {
      if (skip.has(`${cat}|${ep}`)) { skipped.push({ category: cat, endpoint: ep }); continue; }
      const remaining = maxChanges - changes.length;
      if (remaining <= 0) { truncated = true; continue; }
      const d = deepDiff(a?.[cat]?.[ep], b?.[cat]?.[ep], { maxChanges: remaining, ignoreKeys: volatileKeys[ep] });
      for (const c of d.changes) changes.push({ ...c, path: `${cat}.${ep}.${c.path}` });
      if (d.truncated) truncated = true;
    }
  }

  return { changes, truncated, skipped, summary: summarizeChanges(changes) };
}
