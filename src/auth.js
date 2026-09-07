// ─── Cloudflare Access identity ─────────────────────────────────────────────
// Validates the Cf-Access-Jwt-Assertion header (or CF_Authorization cookie)
// against the team's JWKS and returns the acting user's email. No external
// dependencies — WebCrypto only.
//
// Configure via secrets:
//   ACCESS_TEAM_DOMAIN  e.g. "myteam"  (from https://<myteam>.cloudflareaccess.com)
//   ACCESS_AUD          AUD tag of the Access application protecting this worker
//
// When the vars are unset the worker runs in anonymous mode (local dev /
// pre-Access setup) and actions are attributed to "anonymous".

let jwksCache = null;
const JWKS_TTL_MS = 60 * 60 * 1000;

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function fetchJwks(env) {
  if (jwksCache && Date.now() - jwksCache.ts < JWKS_TTL_MS) return jwksCache.keys;
  const team = String(env.ACCESS_TEAM_DOMAIN)
    .replace(/^https?:\/\//, '')
    .replace(/\.cloudflareaccess\.com$/, '')
    .replace(/\/$/, '');
  const res = await fetch(`https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const jwks = await res.json();
  jwksCache = { ts: Date.now(), keys: jwks };
  return jwks;
}

async function verifyAccessJWT(env, jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('malformed JWT');
  const [h, p, s] = parts;

  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
  if (header.alg !== 'RS256') throw new Error(`unsupported alg ${header.alg}`);

  const jwks = await fetchJwks(env);
  let key = (jwks.keys || jwks.public_keys || []).find(k => k.kid === header.kid);
  if (!key) {
    // key may have rotated — retry once with fresh JWKS
    jwksCache = null;
    const fresh = await fetchJwks(env);
    key = (fresh.keys || fresh.public_keys || []).find(k => k.kid === header.kid);
    if (!key) throw new Error('signing key not found');
  }

  const cryptoKey = await crypto.subtle.importKey(
    'jwk', key,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', cryptoKey,
    b64urlToBytes(s),
    new TextEncoder().encode(`${h}.${p}`)
  );
  if (!ok) throw new Error('invalid signature');

  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('token expired');
  const team = String(env.ACCESS_TEAM_DOMAIN).replace(/^https?:\/\//, '').replace(/\.cloudflareaccess\.com$/, '');
  if (payload.iss && !payload.iss.includes(`${team}.cloudflareaccess.com`)) throw new Error('issuer mismatch');

  const aud = env.ACCESS_AUD;
  if (aud) {
    const match = Array.isArray(payload.aud) ? payload.aud.includes(aud) : payload.aud === aud;
    if (!match) throw new Error('audience mismatch');
  }

  return payload;
}

// Returns:
//   { actor: '<email>', authenticated: true }  — valid Access session
//   { actor: 'anonymous', authenticated: false, access_configured: false } — dev mode
//   null — Access is configured but the request is not authenticated/valid
export async function getActor(env, request) {
  if (!env.ACCESS_TEAM_DOMAIN) {
    return { actor: 'anonymous', authenticated: false, access_configured: false };
  }

  let jwt = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!jwt) {
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/(?:^|;\s*)CF_Authorization=([^;]+)/);
    if (m) jwt = m[1];
  }
  if (!jwt) return null;

  try {
    const payload = await verifyAccessJWT(env, jwt);
    // Users have email; service tokens carry their client ID in common_name.
    const actor = payload.email || payload.common_name || payload.sub || 'unknown';
    return { actor, authenticated: true, access_configured: true };
  } catch {
    return null;
  }
}
