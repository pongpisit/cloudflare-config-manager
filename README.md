# Cloudflare Configuration Manager

A tool to fetch, version, audit, and roll back Cloudflare configurations — including **Zero Trust** — across multiple zones and accounts.

## RFP compliance

| Requirement | Implementation |
|---|---|
| Policy versioning | **Delta-based versioning**: the first version is a full snapshot; every later version records *only what changed* (per-endpoint patches + item-level diff detail) with a monotonically increasing per-zone version number. The full state at any version is reconstructed from the chain and verified with SHA-256 state checksums. Versions are created on manual save, on-demand **Check for changes**, hourly **scheduled detection** (cron), and automatically before every rollback. Unchanged saves never create a version. |
| Full change history audit trail | Append-only `audit_log` table records who did what, when, and with what outcome (`snapshot.create/view/delete/diff`, `rollback.dry_run/execute`, `auth.denied`). Every recorded change is browsable per version ("Changes" action), and any two versions — or a version vs live — can be diffed to reconstruct what changed between them. Identity comes from Cloudflare Access (email in every audit entry). |
| Rollback to any previous version | `POST /api/rollback` restores any version, per category. The dry-run response includes the **full state diff (live → target)** so the admin reviews exactly what will change before committing, plus every planned write operation. An automatic pre-rollback safety snapshot is taken (the rollback itself can be rolled back), and post-execution verification re-fetches live state against the target. |

## Architecture

```
index.js              — router: UI, auth gate, CF API proxy, scheduled change detection
src/categories.js     — endpoint catalog (what gets fetched)
src/cfapi.js          — Cloudflare API client + parallel config fetcher
src/auth.js           — Cloudflare Access JWT verification (actor identity)
src/db.js             — D1: version metadata, version counter, tracked zones, append-only audit log
src/store.js          — R2: version payloads + SHA-256 integrity
src/diff.js           — deep JSON diff (id-aware lists, ignores volatile timestamps)
src/versioning.js     — delta computation, application, chain reconstruction, storage strategy
src/snapshots.js      — version/rollback/audit/check API handlers
src/rollback.js       — rollback engine: per-resource planners + executor + verifier
src/ui.js             — single-page UI
schema.sql            — D1 schema (fresh installs)
migrations/           — incremental migrations for existing databases
```

**Bindings:** `DB` (D1 database `fetch-cf-config-db`), `SNAPSHOTS` (R2 bucket `fetch-cf-config-snapshots`).

## Using the tool (UX)

The app is organized into six pages — connection settings are separated from the daily operations:

- **Settings** — connection & session: paste your API token and click **Connect** (zones + the Cloudflare One account are detected automatically). Shows connection status and the recommended token permissions.
- **Overview** (landing after connecting) — the drift dashboard: latest version, version count, last scheduled check and its result for every tracked target, with per-target **Check now** / **Open**. Guided empty states when not connected or before the first baseline exists.
- **AppSec** — the zone-level product page: pick a zone, choose categories (WAF/DDoS/Bot/API Shield, TLS, CDN, DNS + account-level WAF), fetch, results, **AppSec Version Snapshots** (filters, compare bar, Check, Named Snapshot), restore, and zone-vs-zone comparison.
- **Cloudflare One** — the account-level Zero Trust product page, fully independent of zones: its own fetch, results, **Zero Trust Version Snapshots** and restore. No zone selector, no WAF content.
- **Audit Log** — the append-only change history with friendly labels and filters.
- **Reference** — the built-in settings catalog: every captured setting for both products with a plain-English description of what it controls, its API path, and its restore behavior (restorable vs view-only, plus special restore semantics like DNS type+name matching, gateway-list item reconciliation, and new-secrets warnings). Searchable.

Shared: the diff view (appears when a comparison is rendered) and the stepped restore modal.

- **Return visits are zero-setup**: the token, Account ID, selected zone and active page are remembered in the browser (localStorage only, never stored server-side). "Clear session" in the topbar removes them.
- **Product pages self-load**: opening **AppSec** or **Cloudflare One** automatically loads the version history and refreshes the current live configuration (throttled to once a minute per target) — the page always opens on the current state, with a drift banner explaining any unsaved difference. Nothing is ever auto-saved; saving stays explicit.
- **The newest version is badged** in the version table: **current** (green) when it matches the live configuration, **latest — live drifted** (amber) when live has unsaved changes, or **latest** (blue) before a check has run. Every row can be viewed, diffed against live, and restored (rolled back to).
- **Targets Overview** dashboard: drift status of every tracked target — latest version, version count, last scheduled check and its result, with per-target **Check now**.
- **Fetch → drift banner**: after every fetch the UI compares (preview, read-only) against the latest version and shows either *"Matches vN — nothing to save"* or *"Fetched state differs from vN (+a −r ~c)"* with a one-click **Save as new version** and **Review changes**. Before a baseline exists it offers **Save the first version**. Results are marked *"not saved yet"* until handled.
- **Restore** is review-gated: the Execute button stays disabled until a preview (full state diff + planned operations) has been reviewed.
- The fetch button is context-aware: primary *"Fetch & Save First Version"* before a baseline exists, secondary once *"Check for changes"* becomes the daily action.

## Versioning scopes

The tool versions **policy configuration only** — deliberately excluding developer products so deploys and infrastructure churn never create version noise:

| Scope | What it covers | Version key |
|---|---|---|
| **Zone** | **AppSec**: WAF/custom firewall rules, managed rules, overrides, UA rules, lockdowns, rate limits, IP access rules, Bot Management, DDoS L7 overrides, managed headers, Transform/Redirect/Config rules, API Shield, security settings, SSL/certificates · **TLS & network security**: min TLS version, TLS 1.3, HSTS/always-use-HTTPS, HTTP/2/3, IPv6, onion routing, NEL… · **CDN**: cache rules/settings, tiered cache, cache reserve, page rules, minify/polish/Rocket Loader… · **DNS**: records, DNSSEC | zone id |
| **Account (Cloudflare One)** | **Zero Trust**: Access org/apps/policies/groups/service tokens/IdPs, Gateway configuration/lists (including each list's **items**) /locations/rules/proxy endpoints, tunnels + routes + virtual networks, device posture + settings + fallback domains, risk scoring, DLP profiles, **DEX test definitions** (configuration only — test *results* and analytics are never fetched) | account id |

**Intentionally out of scope** (never versioned): Workers scripts/routes, Pages, KV, D1, Queues, R2, AI Gateway, Vectorize, Email Routing, Logpush, Notifications, Load Balancers, Spectrum, Magic WAN/Magic Transit, account members/roles/details, Cloudflare audit logs (volatile), DEX test *results*/analytics (`/dex/tests/overview`), SSL recommendation engine output, seat/licensing usage, and the static Gateway URL-category catalog. Only configuration, settings and rules are captured — runtime data (tunnel status, origin health, fetch timestamps, list item counts, key rotation state, DLP match counters, cert binding status, derived app-linkage counts) is fetched for context but never triggers versions or appears in diffs.

Each scope has its own version history, change detection (on-demand + scheduled), named snapshots, retention, and restore flow. Zone fetches never capture account-level resources — select the **Account — Cloudflare One** target in the UI to fetch, version, check, and restore account-level configuration.

## Delta versioning model

```
v1 (full)  ── v2 (delta) ── v3 (delta) ── … ── v27 (full, chain compacted)
                                📌 named snapshots: full + pinned
```

- **A version is created only when something actually changed.** Saves/checks that find no differences return `no_change` — no version inflation. Runtime state (origin health, tunnel status, log rotation, file sizes, fetch timestamps) never triggers versions.
- A **delta** stores only the endpoints that changed: `[{op:'set', category, endpoint, data}]` plus item-level detail for display, and a `meta` op when the tracked endpoint set itself changed.
- The **full state at any version** is reconstructed by walking `base_version` links down to the nearest full snapshot and applying deltas forward. Reconstruction is verified against the recorded `state_checksum` — tampered or corrupted data fails loudly.
- A **full snapshot** is forced when: it's the first version, the delta exceeds 50% of the base payload, or 25 consecutive deltas have accumulated (chain compaction).
- **Named snapshots** (PAN SCM-style): save the current configuration under a name (≤64 chars, default `config_YYYY-MM-DD-HHMMSS`). Named snapshots are always stored full and are **pinned** — exempt from retention pruning — giving you known-good states you can always return to.
- **Retention** (PAN SCM-style: 200 versions / 6 months): the newest 200 non-named versions and anything newer than 180 days are kept per zone; older excess versions are soft-deleted automatically (payloads retained for delta-chain integrity, prunes recorded in the audit trail). Override with `RETENTION_LIMIT` / `RETENTION_DAYS` vars (0 = unlimited).
- **Restore bumps the version number** (PAN SCM semantics): executing a rollback records the restored live state as a new version (trigger `rollback`), so the restore itself is part of the history and the history stays monotonic.
- **Volatile endpoints** (`audit_logs`) never trigger versions, never enter deltas, and are excluded from rollback previews (they can never be restored). DEX test *definitions* (`devices/dex_tests`) are real config and are versioned/restored — the analytics endpoint is never fetched.
- **Volatile keys** — runtime fields inside otherwise-config payloads never trigger versions, diffs or restore comparisons: tunnel `status`/`connections`/`remote_config`, Access key rotation state (`last_key_rotation_at`, `days_until_next_rotation`), DLP match counters (`allowed_match_count`), Gateway certificate `binding_status`, and the derived Access policy `app_count`.
- Endpoints that could not be fetched (permissions) keep their last recorded value — they are never treated as removed.

### Change detection

| Mode | How |
|---|---|
| **Automatic (default)** | Cron (`*/5 * * * *`) — every 5 minutes the worker polls Cloudflare's audit log (1 API call). If any new activity is found, the full drift comparison runs for every tracked target and drift is recorded as a new delta version **with attribution**: the version label names who made the change and what they did (from the audit entries). No new audit activity → the comparison is skipped. Every WAF / Zero Trust change becomes a version within ~5 minutes, hands-off. |
| Manual save | UI "Save as Version" after a fetch — creates a version only if the fetched config differs from the latest version |
| On-demand check | UI "Check for changes" — fetches live with your session token, records drift as a delta version |

Requires the stored read-only token: `npx wrangler secret put CF_API_TOKEN`.

Enable scheduled detection:
```bash
npx wrangler secret put CF_API_TOKEN   # read-only Cloudflare API token
```


## How rollback works

 1. **Version** — a configuration capture (full or delta), tagged per zone with version number, label, actor, and the exact endpoint list used to fetch it.
 2. **Diff** — any version can be compared with the current live configuration (`Diff vs live`), with any other version (compare bar), and every version's own recorded delta is browsable (`Changes` action).
 3. **Rollback (Restore)** — stepped, review-before-commit flow:
    - **1 · Select scope** — pick categories; the Execute button is disabled until a preview has been reviewed.
    - **2 · Review changes** — Preview (dry run) shows the **state diff (live → target version)** — exactly what will be added/removed/changed — plus every planned write operation, with staged progress feedback while it runs.
    - **3 · Result** — Execute applies the restore: an automatic **pre-rollback safety version** is recorded first (the restore itself can be undone), operations are applied, each endpoint is re-fetched and **verified** against the target, a summary is shown, and the restored state is recorded as a **new version** (a restore bumps the version number).
 4. Every action lands in the audit log with the signed-in user's email.

### Restorable resources (policy scope)

| Type | Resources |
|---|---|
| WAF & firewall | firewall rules, WAF managed rules + overrides, user-agent rules, lockdowns, rate limits, IP access rules (zone + account), custom WAF rules (zone + account) |
| Rules engine | transform, redirect, config, cache, DDoS L7 ruleset phases |
| Bot & API security | bot management, API Shield configuration |
| Zone security settings | security_level, challenge_ttl, browser_check, hotlink, email obfuscation, SSE, security_header, scrape_shield, SSL |
| TLS & network | min TLS version, TLS 1.3, always_use_https, automatic_https_rewrites, HTTP/2/3, zero RTT, opportunistic encryption/onion, IPv6, websockets, pseudo IPv4, IP geolocation, NEL |
| CDN & DNS | cache rules/settings, tiered cache, cache reserve, page rules, minify/polish/Rocket Loader/etc., DNS records (reconciled by type+name), managed headers, speed brain |
| Cloudflare One | Access org settings, apps (incl. inline policies), reusable policies, groups, service tokens, identity providers, tunnels, tunnel routes, virtual networks, Gateway configuration, DNS locations, **lists — including their items (appended/removed individually via the list PATCH API)**, all Gateway policies, proxy endpoints, device posture rules + integrations, device settings, fallback domain list, risk scoring, DEX test definitions (create/update/delete via the `devices/dex_tests` API) |

View-only (reported in rollback results but never written): certificates, custom hostnames, DNSSEC, workers/pages, DLP, logs, seats, DEX, Access CA certs & keys, Magic Transit, and anything the snapshot couldn't fetch.

### Safety guards

- Lists at the page-size cap (possible truncation) are **refused** rather than partially reconciled.
- Snapshots fetched with `action=` filters (partial Gateway lists) are treated as view-only.
- `pre_rollback` snapshots cannot be deleted without `?force=true`.
- Snapshot deletes are soft (metadata retained, deletion audited).
- Warnings on resources whose secrets cannot round-trip (service tokens, tunnels, identity providers).
- Every write op is reported individually; a failed op never aborts the rest.

## Authentication

The worker is protected by **Cloudflare Access** (enforced at the account's edge). The worker additionally validates the `Cf-Access-Jwt-Assertion` and records the user's email as the audit actor. Configured via secrets:

```
npx wrangler secret put ACCESS_TEAM_DOMAIN   # e.g. "myteam"
npx wrangler secret put ACCESS_AUD            # AUD tag of the Access application
```

To temporarily disable worker-side validation (edge enforcement still applies): delete both secrets.

> While `ACCESS_TEAM_DOMAIN` is unset the worker runs in **anonymous mode** — intended for `wrangler dev` only.

## API

| Method & path | Description |
|---|---|
| `GET /api/categories` | Category metadata |
| `GET /api/zones` | List zones (proxied with user token) |
| `GET /api/configs/:zoneId?cats=&accountId=` | Fetch current **zone-level** configuration (account endpoints excluded) |
| `GET /api/account-configs/:accountId` | Fetch all **account-level** configuration (Cloudflare One, account WAF, Magic WAN…) |
| `POST /api/snapshots` | Save fetched config — creates a new version **only if changed** (`{created, no_change, version, kind, change_summary}`). Pass `name` to save a **named snapshot** (pinned, always full) |
| `GET /api/snapshots?zone_id=` | List versions for a zone (`&include_deleted=true`) |
| `GET /api/snapshots/:id` | Full reconstructed state at that version (checksum-verified) |
| `GET /api/versions/:id/changes` | The recorded delta of a version (what changed vs its base) |
| `POST /api/versions/check` | Fetch live now and record drift as a new version if anything changed |
| `DELETE /api/snapshots/:id` | Soft delete (`?force=true` for pre-rollback snapshots) |
| `GET /api/snapshots/:id/diff?vs=live\|<snapshotId>` | Structured diff (version vs live, or version vs version) |
| `POST /api/rollback` | Body: `{snapshot_id, categories?, dry_run}` — response includes `state_diff` (live → target) + planned `report` |
| `GET /api/audit?zone_id=&actor=&action=&from=&to=&limit=&offset=` | Query the audit log |
| `POST /api/diff` | Diff two arbitrary payloads |
| `GET /api/whoami` | Current actor |

## API token permissions

- **Read (fetch/snapshot/diff):** Zone — Zone, DNS, SSL/Certificates, Firewall Services, Page Rules, Cache, Workers Routes, Load Balancers, Logs, Bot Management, API Shield (read). Account — Settings, Workers Scripts, Tunnel, Zero Trust (Access/Gateway), Magic Transit, DLP, R2, KV, D1, Queues, Notifications (read).
- **Edit (rollback):** Zone — DNS, Firewall Services, Page Rules, Cache Purge, Zone Settings, Page Rules. Account — Zero Trust (Access: Apps/Policies/Groups/Service Tokens/IdPs/Organizations; Gateway: Configuration/Lists/Locations/Rules/Proxy Endpoints), Cloudflare Tunnel, Firewall Services, Rulesets, Device Settings/Posture, Rulesets (edit).

## Operations

```bash
npx wrangler dev                 # local dev (local D1/R2, anonymous mode)
npm test                         # unit tests: rollback planners, diff engine, versioning, retention
npm run test:ui                  # UI-driven restore E2E: runs the real client script against
                                  # wrangler dev + real Cloudflare (needs CF_API_TOKEN, ZONE_ID)
npx wrangler deploy              # deploy

# DB maintenance
npx wrangler d1 execute fetch-cf-config-db --remote --file=./schema.sql
npx wrangler d1 execute fetch-cf-config-db --remote \
  --command "SELECT id, ts, actor, action, outcome FROM audit_log ORDER BY id DESC LIMIT 20"

# Access secrets
npx wrangler secret list
npx wrangler secret delete ACCESS_AUD
```

## Notes & limitations

- The API token is provided per browser session and never persisted server-side; version payloads contain the configuration data the token could read at capture time. (The optional `CF_API_TOKEN` secret used by scheduled checks is stored as a Worker secret.)
- Rollback re-creates resources that no longer exist; resources with server-generated secrets (service tokens, tunnels, IdPs) get **new** secrets — flagged with warnings in the dry-run preview and result report.
- Endpoints with more items than the page cap (100, DNS 500) are skipped for reconciliation — extend `per_page`/pagination in `src/categories.js` and `src/rollback.js` if needed.
- First real rollback should be exercised against a test zone: dry-run preview → review the state diff → execute → confirm the verification checks pass.
- Scheduled checks use the tracked endpoint list of each zone's latest version; the list updates whenever a full version is recorded or the endpoint set changes (recorded as a `meta` delta op).
- Local D1 databases created before delta versioning need `migrations/002-delta-versioning.sql` applied.

## Usage & cost estimate

**What each feature consumes** (measured against this system's real behavior — 86 endpoints in the catalog):

| Feature | Workers requests | Subrequests / invocation | D1 reads | D1 writes | R2 ops |
|---|---|---|---|---|---|
| Cron tick, no changes (`*/5`) | 1 (scheduled) | 1 (audit-log poll) | ~3 (watermark) | 0 | 0 |
| Cron tick with drift → new version | 1 (scheduled) | ~62 zone / ~31 account | ~100 (versions, chain) | ~10 (version + audit + target) | 1 Class A PUT |
| UI product page open (auto-load) | 3 (list + fetch + drift preview) | ~62 / ~31 | ~200 | 0–10 | 1–3 Class B |
| Version view / diff | 1 | 0 | 1–25 | 1 (audit) | 1–3 Class B |
| Restore: preview then execute | 2 | ~154 total (live + ops + verify) | ~50 | ~60 (safety snap + version + audit) | 2 Class A + ~3 Class B |

**Monthly aggregate** (personal / small-team use — 1–3 admins, 3 tracked targets, 10–100 changes recorded):

| Component | Est. monthly usage | Free allowance | Headroom | Cost |
|---|---|---|---|---|
| **Workers requests** | 10–20K (cron = 8,640 fixed + UI) | 100K/day (free plan) | >100× | $0 |
| **Workers subrequests / invocation** | up to ~154 (restore) | **50/request on free plan** | — | ⚠ see below |
| **Workers CPU time** | 20–200ms per fetch/diff | 10ms/request (free plan) | — | ⚠ see below |
| **D1 rows read** | ~50–150K | 5M/day | >500× | $0 |
| **D1 rows written** | ~3–10K | 100K/day | >100× | $0 |
| **D1 storage** | ~25–50MB after a year | 5GB | >100× | $0 |
| **R2 storage** | ~2.5MB at retention cap (200 versions/target; full snapshots measure 5–25KB gzipped, deltas ~2KB) | 10GB | >1,000× | $0 |
| **R2 Class A writes** | ~300–500 | 1M/mo | >2,000× | $0 |
| **R2 Class B reads** | ~1–3K | 10M/mo | >3,000× | $0 |
| **Cloudflare Access** | 1–3 users + 1 service token | 50 users | >10× | $0 |
| **Cloudflare API calls** (outbound, free) | ~20–30K | rate limit 1,200/5min | ~20× | $0 |

**The one thing that costs money: Workers Paid ($5/month, minimum).** The free plan caps each invocation at **50 subrequests and 10ms CPU** — an AppSec fetch needs ~62 subrequests and the delta diffing can exceed 10ms CPU, so full fetches, drift checks and restores require the paid plan (1,000 subrequests, 30M CPU-ms/mo included). Everything else stays in free tiers even on the paid plan.

**Realistic monthly bill: $5 flat.** Overage would require millions of requests or a change volume thousands of times higher than typical admin use.

## Deployment

1. Copy the config template and fill in your ids:
   ```bash
   cp wrangler.example.toml wrangler.toml
   # edit: account_id and the D1 database_id (create it with the command below)
   ```
2. Create the bindings and deploy:
   ```bash
   npx wrangler d1 create fetch-cf-config-db        # copy the id into wrangler.toml
   npx wrangler r2 bucket create fetch-cf-config-snapshots
   npx wrangler d1 migrations apply fetch-cf-config-db --remote
   npx wrangler deploy
   ```
3. Set secrets:
   ```bash
   npx wrangler secret put CF_API_TOKEN        # read-only Cloudflare API token used by the cron
   npx wrangler secret put ACCESS_TEAM_DOMAIN  # e.g. "myteam" from <myteam>.cloudflareaccess.com
   npx wrangler secret put ACCESS_AUD           # AUD tag of the Access application
   ```
4. Protect the deployed worker with a **Cloudflare Access** application so only you can reach it.

`wrangler.toml` (your real ids) is git-ignored; `wrangler.example.toml` is the committed template.
