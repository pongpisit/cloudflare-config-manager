// ─── R2 snapshot payload store ──────────────────────────────────────────────
// Full config payloads live in R2 (they can exceed D1 row limits); D1 keeps
// metadata plus a SHA-256 checksum for integrity verification on every read.

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Deterministic checksum of a state object (used for reconstructed-state
// integrity verification of delta versions).
export async function objectChecksum(obj) {
  return sha256Hex(JSON.stringify(obj));
}

export async function putSnapshotPayload(env, r2Key, obj) {
  const body = JSON.stringify(obj);
  const checksum = await sha256Hex(body);
  await env.SNAPSHOTS.put(r2Key, body, {
    httpMetadata: { contentType: 'application/json' },
    customMetadata: { checksum },
  });
  return { checksum, size: body.length };
}

export async function getSnapshotPayload(env, r2Key, expectedChecksum) {
  const obj = await env.SNAPSHOTS.get(r2Key);
  if (!obj) throw new Error('Snapshot payload missing from object storage');
  const body = await obj.text();
  const checksum = await sha256Hex(body);
  if (expectedChecksum && checksum !== expectedChecksum) {
    throw new Error(`Snapshot payload integrity check failed (expected ${expectedChecksum}, got ${checksum})`);
  }
  return JSON.parse(body);
}
