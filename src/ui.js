// ─── Single-page UI — two dedicated pages ────────────────────────────────────
//   • AppSec (Zone)     — zone-level configuration: pick a zone, categories,
//                         fetch, versions, restore, compare zones
//   • Cloudflare One    — account-level configuration (Zero Trust, account
//                         WAF/access rules, DLP): completely independent of
//                         zones — its own fetch, versions and restore
//   • Audit Log         — append-only change history
// Shared: credentials (token + account id), targets overview, diff card,
// restore modal. Served by the worker at GET /.
// NOTE: the client script below deliberately avoids template literals and ${}
// so it can live inside this module's template string.

export const UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Configuration Manager</title>
  <style>
    :root {
      --cf-orange: #f6821f;
      --cf-blue: #003682;
      --cf-dark: #1d1d1d;
      --cf-surface: #ffffff;
      --cf-bg: #f0f2f5;
      --cf-border: #e0e0e0;
      --cf-success: #1e8a44;
      --cf-danger: #c0392b;
      --cf-muted: #6b7280;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--cf-bg); color: var(--cf-dark); }
    .topbar { background: var(--cf-blue); color: #fff; padding: 14px 24px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .topbar-logo { font-size: 22px; font-weight: 800; color: var(--cf-orange); letter-spacing: -0.5px; }
    .topbar-title { font-size: 16px; font-weight: 500; opacity: 0.9; }
    .topbar-right { margin-left: auto; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .topbar-nav { display: flex; gap: 18px; align-items: center; }
    .topbar-link { color: #fff; font-size: 13.5px; text-decoration: none; opacity: .8; cursor: pointer; padding-bottom: 3px; border-bottom: 2px solid transparent; }
    .topbar-link:hover { opacity: 1; text-decoration: underline; }
    .topbar-link.active { opacity: 1; font-weight: 700; border-bottom-color: var(--cf-orange); }
    .user-pill { font-size: 12.5px; background: rgba(255,255,255,.14); padding: 5px 12px; border-radius: 14px; }
    .user-pill.pill-warn { background: #f59e0b; color: #422006; font-weight: 600; }
    /* More menu (overflow nav) */
    .nav-more { position: relative; }
    .more-menu { position: absolute; right: 0; top: calc(100% + 10px); background: #fff; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,.2); min-width: 170px; padding: 6px 0; z-index: 60; }
    .more-menu a.topbar-link { display: block; color: var(--cf-dark); padding: 10px 16px; opacity: 1; border-bottom: none; }
    .more-menu a.topbar-link:hover { background: #f0f2f5; text-decoration: none; opacity: 1; }
    .more-menu a.topbar-link.active { color: var(--cf-orange); font-weight: 700; }
    .more-sep { height: 1px; background: var(--cf-border); margin: 6px 0; }
    .main { max-width: 1100px; margin: 28px auto; padding: 0 16px; display: flex; flex-direction: column; gap: 20px; }
    .card { background: var(--cf-surface); border-radius: 10px; box-shadow: 0 1px 6px rgba(0,0,0,.08); padding: 22px 24px; }
    .card h2 { font-size: 15px; font-weight: 700; color: var(--cf-blue); margin-bottom: 16px; border-bottom: 1px solid var(--cf-border); padding-bottom: 10px; }
    .card h2 .sub { font-weight: 400; color: var(--cf-muted); font-size: 12.5px; }
    .form-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
    .field { display: flex; flex-direction: column; gap: 5px; flex: 1; min-width: 200px; }
    .field label { font-size: 13px; font-weight: 600; color: var(--cf-muted); text-transform: uppercase; letter-spacing: .4px; }
    .field input, .field select { padding: 9px 12px; border: 1px solid var(--cf-border); border-radius: 6px; font-size: 14px; background: #fafafa; transition: border-color .2s; }
    .field input:focus, .field select:focus { outline: none; border-color: var(--cf-orange); background: #fff; }
    .btn { padding: 9px 20px; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity .2s, background .2s; white-space: nowrap; }
    .btn-primary { background: var(--cf-orange); color: #fff; }
    .btn-secondary { background: var(--cf-blue); color: #fff; }
    .btn-outline { background: transparent; color: var(--cf-blue); border: 1.5px solid var(--cf-blue); }
    .btn-danger { background: transparent; color: var(--cf-danger); border: 1.5px solid var(--cf-danger); }
    .btn:hover { opacity: .88; }
    .btn:disabled { opacity: .45; cursor: not-allowed; }
    .alert { padding: 10px 14px; border-radius: 6px; font-size: 13.5px; margin-bottom: 4px; }
    .alert-success { background: #d1fae5; color: #065f46; }
    .alert-danger  { background: #fee2e2; color: #7f1d1d; }
    .alert-warning { background: #fef3c7; color: #78350f; }
    .hidden { display: none !important; }
    .muted { color: var(--cf-muted); font-size: 12.5px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    /* Category grid (zone page only) */
    .cat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin: 10px 0 16px; }
    .cat-card { border: 2px solid var(--cf-border); border-radius: 8px; padding: 10px 14px; cursor: pointer; transition: border-color .15s, background .15s; user-select: none; }
    .cat-card.selected { border-color: var(--cf-orange); background: #fff7ed; }
    .cat-card input[type=checkbox] { display: none; }
    .cat-card-label { font-size: 13.5px; font-weight: 600; color: var(--cf-dark); }
    .select-all-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; font-size: 13px; }
    /* Results */
    .results-toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; }
    .results-toolbar .info { font-size: 13px; color: var(--cf-muted); margin-left: auto; }
    .tab-bar { display: flex; gap: 0; border-bottom: 2px solid var(--cf-border); margin-bottom: 14px; overflow-x: auto; }
    .tab { padding: 8px 16px; font-size: 13px; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; color: var(--cf-muted); white-space: nowrap; }
    .tab.active { color: var(--cf-orange); border-bottom-color: var(--cf-orange); }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    pre { background: #1e1e2e; color: #cdd6f4; padding: 16px; border-radius: 8px; overflow: auto; max-height: 540px; font-size: 12.5px; line-height: 1.6; }
    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; font-size: 11.5px; text-transform: uppercase; letter-spacing: .4px; color: var(--cf-muted); padding: 8px 10px; border-bottom: 2px solid var(--cf-border); }
    td { padding: 8px 10px; border-bottom: 1px solid var(--cf-border); vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    .link-btn { background: none; border: none; color: var(--cf-blue); font-size: 12.5px; font-weight: 600; cursor: pointer; padding: 2px 6px; }
    .link-btn:hover { text-decoration: underline; }
    .link-danger { color: var(--cf-danger); }
    .row-actions { white-space: nowrap; }
    /* Badges & chips */
    .badge { display: inline-block; font-size: 11.5px; font-weight: 700; padding: 2px 9px; border-radius: 11px; margin-right: 6px; }
    .badge-added { background: #dcfce7; color: #166534; }
    .badge-removed { background: #fee2e2; color: #991b1b; }
    .badge-changed { background: #dbeafe; color: #1e40af; }
    .badge-warn { background: #fef3c7; color: #78350f; }
    .badge-auto { background: #ede9fe; color: #5b21b6; }
    .badge-named { background: #fef08a; color: #713f12; }
    .badge-acct { background: #dbeafe; color: #1e40af; }
    .chip { font-size: 11.5px; padding: 2px 8px; border-radius: 12px; font-weight: 500; }
    .chip-ok { background: #dcfce7; color: #166534; }
    .chip-skip { background: #f3f4f6; color: #6b7280; }
    .chip-err { background: #fee2e2; color: #991b1b; }
    .chip-warn { background: #fef3c7; color: #78350f; }
    /* Diff */
    .diff-summary { margin: 10px 0; }
    .diff-list { display: flex; flex-direction: column; gap: 8px; max-height: 560px; overflow: auto; padding-right: 4px; }
    .diff-row { display: flex; flex-direction: column; gap: 3px; background: #fafafa; border: 1px solid var(--cf-border); border-radius: 6px; padding: 8px 10px; font-size: 12.5px; }
    .diff-path { font-family: ui-monospace, Menlo, monospace; font-weight: 600; word-break: break-all; }
    .diff-val { font-family: ui-monospace, Menlo, monospace; color: var(--cf-muted); word-break: break-all; white-space: pre-wrap; }
    .diff-val.plus { color: #166534; }
    .diff-val.minus { color: #991b1b; }
    .diff-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.5; background: #1e1e2e; color: #cdd6f4; padding: 8px 12px; border-radius: 6px; margin: 5px 0 0 0; overflow: auto; max-height: 220px; white-space: pre-wrap; word-break: break-all; }
    .diff-code.plus { border-left: 3px solid #22c55e; }
    .diff-code.minus { border-left: 3px solid #ef4444; }
    .diff-empty { padding: 20px; text-align: center; color: var(--cf-muted); }
    .diff-group { border: 1px solid var(--cf-border); border-radius: 8px; margin-top: 8px; }
    .diff-group summary { cursor: pointer; padding: 8px 12px; font-size: 13px; list-style: none; background: #fafafa; border-radius: 8px; }
    .diff-group summary::-webkit-details-marker { display: none; }
    .diff-group .diff-list { padding: 8px 10px; }
    /* Rollback report */
    .rb-entries { margin-top: 12px; display: flex; flex-direction: column; gap: 8px; }
    .rb-entry { border: 1px solid var(--cf-border); border-radius: 6px; padding: 0; }
    .rb-entry summary { cursor: pointer; padding: 8px 12px; font-size: 13px; list-style: none; }
    .rb-entry summary::-webkit-details-marker { display: none; }
    .rb-note, .rb-op { padding: 2px 14px 6px 14px; font-size: 12.5px; }
    .rb-op { font-family: ui-monospace, Menlo, monospace; }
    .rb-op.diff-added { color: #166534; }
    .rb-op.diff-removed { color: #991b1b; }
    .rb-entry .alert { margin: 6px 14px; }
    .rb-section-title { font-size: 13.5px; font-weight: 700; color: var(--cf-blue); margin: 16px 0 8px 0; }
    .rb-diff { padding: 8px 14px 10px 14px; }
    .rb-diff .diff-list { max-height: 320px; }
    /* Audit */
    .audit-pre { max-height: 220px; overflow: auto; font-size: 11.5px; margin-top: 6px; }
    .filter-bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 14px; }
    .filter-bar .field { min-width: 140px; flex: 0 1 auto; }
    .audit-nav { display: flex; gap: 10px; align-items: center; margin-top: 12px; font-size: 13px; color: var(--cf-muted); }
    /* Modal */
    .modal-overlay { position: fixed; inset: 0; background: rgba(15,23,42,.55); display: flex; align-items: flex-start; justify-content: center; padding: 40px 16px; z-index: 50; overflow-y: auto; }
    .modal { background: #fff; border-radius: 10px; max-width: 780px; width: 100%; padding: 24px 26px; box-shadow: 0 20px 60px rgba(0,0,0,.25); }
    .modal-head h3 { color: var(--cf-blue); font-size: 17px; margin-bottom: 4px; }
    .modal-note { font-size: 13px; margin: 12px 0; }
    .modal-cats { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin: 12px 0 16px; }
    .modal-cat { display: flex; gap: 8px; align-items: center; border: 1.5px solid var(--cf-border); border-radius: 6px; padding: 8px 10px; font-size: 13px; cursor: pointer; }
    .modal-cat input { cursor: pointer; }
    .modal-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    #rollback-result { margin-top: 16px; }
    .rb-steps { display: flex; gap: 6px; margin: 14px 0 4px 0; flex-wrap: wrap; }
    .rb-step { font-size: 12px; font-weight: 700; color: var(--cf-muted); background: #f3f4f6; padding: 4px 12px; border-radius: 12px; }
    .rb-step.active { color: #fff; background: var(--cf-orange); }
    .rb-spinner { display: inline-block; width: 12px; height: 12px; border: 2px solid #78350f; border-top-color: transparent; border-radius: 50%; margin-right: 6px; vertical-align: -1px; animation: rbspin 0.8s linear infinite; }
    @keyframes rbspin { to { transform: rotate(360deg); } }
    /* Progress */
    .progress-bar { height: 4px; background: var(--cf-border); border-radius: 2px; overflow: hidden; margin-top: 8px; }
    .progress-fill { height: 100%; background: var(--cf-orange); transition: width .3s; }
    .status-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="topbar">
    <span class="topbar-logo">&#9729; CF</span>
    <span class="topbar-title">Configuration Manager</span>
    <div class="topbar-right">
      <div class="topbar-nav">
        <a class="topbar-link" id="nav-overview" onclick="showPage('overview')">Overview</a>
        <a class="topbar-link" id="nav-appsec" onclick="showPage('appsec')">AppSec</a>
        <a class="topbar-link" id="nav-one" onclick="showPage('one')">Cloudflare One</a>
        <div class="nav-more">
          <a class="topbar-link" id="nav-more" onclick="toggleMoreMenu(event)">More &#9662;</a>
          <div class="more-menu hidden" id="more-menu">
            <a class="topbar-link" id="nav-audit" onclick="showPage('audit');closeMoreMenu()">Audit Log</a>
            <a class="topbar-link" id="nav-reference" onclick="showPage('reference');closeMoreMenu()">Reference</a>
            <a class="topbar-link" id="nav-settings" onclick="showPage('settings');closeMoreMenu()">Settings</a>
            <div class="more-sep"></div>
            <a class="topbar-link" id="clear-session-btn" style="display:none" onclick="closeMoreMenu();clearSession()">Clear session</a>
          </div>
        </div>
      </div>
      <span class="user-pill" id="session-pill" style="display:none"></span>
      <span class="user-pill" id="user-pill">Loading…</span>
    </div>
  </div>

  <div class="main">
    <div id="alert-container"></div>

    <!-- ══════════════ PAGE: Overview (landing) ══════════════ -->
    <div id="page-overview" class="hidden">
      <div class="card hidden" id="overview-empty-card">
        <h2>Targets Overview</h2>
        <div id="overview-empty-body" class="muted" style="padding:6px 0 10px 0;font-size:13.5px;line-height:1.7"></div>
        <div class="form-row" id="overview-empty-actions"></div>
      </div>
    <!-- Targets Overview (drift dashboard) -->
    <div class="card hidden" id="overview-card">
      <h2>Targets Overview <span class="sub">— checked automatically every 5 minutes; changes become versions</span></h2>
      <div class="results-toolbar">
        <button class="btn btn-outline" onclick="loadOverview()">Refresh</button>
        <span class="info" id="overview-info"></span>
      </div>
      <table>
        <thead>
          <tr><th>Target</th><th>Scope</th><th>Latest</th><th>Versions</th><th>Last check</th><th>Result</th><th>Actions</th></tr>
        </thead>
        <tbody id="overview-tbody"></tbody>
      </table>
      </div>
    </div>

    <!-- ══════════════ PAGE: Settings ══════════════ -->
    <div id="page-settings" class="hidden">
    <div class="card">
      <h2>Settings — Connection &amp; Session</h2>
      <div class="form-row">
        <div class="field">
          <label>API Token</label>
          <input type="password" id="api-token" placeholder="Paste token — no 'Bearer' prefix needed">
        </div>
        <div class="field" style="max-width:320px">
          <label>Account ID <span style="font-weight:400;color:#aaa">(enables the Cloudflare One page)</span></label>
          <input type="text" id="account-id" placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" onchange="onAccountIdChange()">
        </div>
        <button class="btn btn-primary" id="load-zones-btn" onclick="loadZones()">Connect</button>
      </div>
      <div class="muted" style="font-size:12px;margin-top:8px">The token is remembered on this device (browser localStorage only, never stored server-side) — use <b>Clear session</b> in the topbar to remove it. The Account ID is auto-detected from the token.</div>
      <details style="margin-top:14px">
        <summary style="cursor:pointer;font-size:13px;color:var(--cf-blue);font-weight:600">Recommended token permissions</summary>
        <div style="font-size:12.5px;line-height:1.8;margin-top:8px;color:var(--cf-muted);background:#f8f9fa;padding:10px 14px;border-radius:6px;border-left:3px solid var(--cf-orange)">
          <b>Products:</b> <b>AppSec</b> (zone-level WAF, DDoS, Bot, API Shield, TLS, CDN, DNS + account-level WAF custom rules and IP access rules) and <b>Cloudflare One</b> (pure Zero Trust, account-level). Developer products (Workers, Pages, KV, D1, R2, Queues, LB, Spectrum, Magic WAN) are intentionally not versioned.<br>
          <b>Zone (All Zones — Read):</b> DNS, SSL/Certificates, Firewall Services, Page Rules, Cache Purge, Zone Settings, Bot Management, API Shield<br>
          <b>Account (Read):</b> Zero Trust (Access, Gateway, Cloudflare Tunnel, Device Posture), DLP<br>
          <b>For restore (Edit):</b> the same permissions with Edit — plus Account: Firewall Services and Rulesets (account-level WAF and IP access rules).<br>
          <i>Endpoints your token cannot access are silently skipped. Restore requires Edit permissions for the categories you roll back.</i>
        </div>
      </details>
    </div>
      <div id="settings-status" class="muted" style="margin-top:12px;font-size:13px"></div>
    </div>
    </div>

    <!-- ══════════════ PAGE: AppSec (Zone) ══════════════ -->
    <div id="page-appsec">
      <div class="card hidden" id="zone-card">
        <h2>AppSec — WAF &amp; Security <span class="sub">— zone-level WAF/DDoS/Bot/API Shield + TLS/CDN/DNS, plus account-level WAF</span></h2>
        <div class="form-row" style="margin-bottom:10px">
          <div class="field">
            <label>Zone</label>
            <select id="zone-select" onchange="zoneChanged()"></select>
          </div>
        </div>
        <div class="muted" id="scope-note" style="font-size:12.5px;margin-bottom:12px"></div>
        <label style="font-size:13px;font-weight:600;color:var(--cf-muted);text-transform:uppercase;letter-spacing:.4px">Select Categories</label>
        <div class="select-all-row" style="margin-top:8px">
          <input type="checkbox" id="cat-all" checked onchange="toggleAllCats(this.checked)">
          <label for="cat-all" style="cursor:pointer;font-weight:600">All Categories</label>
        </div>
        <div class="cat-grid" id="cat-grid"></div>
        <div class="form-row">
          <button class="btn btn-primary" id="zone-fetch-btn" onclick="fetchConfigs('zone')">Fetch &amp; Save First Version</button>
          <button class="btn btn-outline" id="compare-btn" onclick="showCompare()" style="display:none">Compare with Zone</button>
        </div>
        <div id="zone-progress-area" class="hidden" style="margin-top:12px">
          <div style="font-size:13px;color:var(--cf-muted)" id="zone-progress-label">Fetching...</div>
          <div class="progress-bar"><div class="progress-fill" id="zone-progress-fill" style="width:0%"></div></div>
          <div class="status-chips" id="zone-status-chips"></div>
        </div>
      </div>

      <div class="card hidden" id="zone-results-card">
        <h2>Zone Results</h2>
        <div id="zone-drift-banner" class="hidden"></div>
        <div class="results-toolbar">
          <button class="btn btn-secondary" onclick="copyResults('zone')">Copy JSON</button>
          <button class="btn btn-outline" onclick="downloadResults('zone')">Download JSON</button>
          <button class="btn btn-outline" onclick="saveVersion('zone')">Save as Version</button>
          <span class="info" id="zone-results-info"></span>
        </div>
        <div class="tab-bar" id="zone-tab-bar"></div>
        <div id="zone-tab-panels"></div>
      </div>

      <div class="card" id="zone-versions-card">
        <h2>AppSec Version Snapshots <span class="sub">— the newest version is the current baseline; restore any version to roll back to it</span></h2>
        <div class="results-toolbar">
          <button class="btn btn-outline" onclick="loadVersions('zone')">Refresh</button>
          <button class="btn btn-primary" id="zone-check-btn" onclick="checkChanges('zone')">Check for changes</button>
          <button class="btn btn-secondary" id="zone-named-btn" onclick="saveNamedSnapshot('zone')">Save Named Snapshot</button>
          <button class="btn btn-outline" onclick="toggleBlock('zone-ver-filters', this)">Filters &#9662;</button>
          <button class="btn btn-outline" onclick="toggleBlock('zone-compare-bar', this)">Compare versions &#9662;</button>
          <span class="info" id="zone-versions-info"></span>
        </div>
        <div class="filter-bar hidden" id="zone-ver-filters">
          <div class="field" style="min-width:130px">
            <label>Trigger</label>
            <select id="zone-ver-filter-trigger" onchange="renderVersions('zone')">
              <option value="">All</option>
              <option value="manual">Manual</option>
              <option value="scheduled">Scheduled</option>
              <option value="pre_rollback">Pre-rollback</option>
              <option value="rollback">Restore</option>
            </select>
          </div>
          <div class="field" style="min-width:110px">
            <label>Kind</label>
            <select id="zone-ver-filter-kind" onchange="renderVersions('zone')">
              <option value="">All</option>
              <option value="named">Named</option>
              <option value="full">Full</option>
              <option value="delta">Delta</option>
            </select>
          </div>
          <div class="field" style="flex:1;min-width:180px">
            <label>Search</label>
            <input type="text" id="zone-ver-filter-search" placeholder="version, description, actor…" oninput="renderVersions('zone')">
          </div>
          <button class="btn btn-outline" onclick="resetVerFilters('zone')">Reset filters</button>
        </div>
        <table>
          <thead>
            <tr><th>Version</th><th>Object changes</th><th>Date</th><th>Created by</th><th>Description</th><th>Kind</th><th>Actions</th></tr>
          </thead>
          <tbody id="zone-versions-tbody"><tr><td colspan="7" class="muted" style="padding:14px">Loading…</td></tr></tbody>
        </table>
        <div class="results-toolbar hidden" style="margin-top:14px" id="zone-compare-bar">
          <select id="zone-cmp-a" style="padding:8px;border:1px solid var(--cf-border);border-radius:6px;font-size:13px;min-width:220px"></select>
          <span class="muted">vs</span>
          <select id="zone-cmp-b" style="padding:8px;border:1px solid var(--cf-border);border-radius:6px;font-size:13px;min-width:220px"></select>
          <button class="btn btn-outline" onclick="compareVersions('zone')">Compare versions</button>
        </div>
      </div>

      <div class="card hidden" id="compare-card">
        <h2>Compare Zones</h2>
        <div class="form-row" style="margin-bottom:12px">
          <div class="field">
            <label>Second Zone</label>
            <select id="compare-zone-select"></select>
          </div>
          <div class="field" style="max-width:220px">
            <label>Category</label>
            <select id="compare-cat-select"></select>
          </div>
          <button class="btn btn-primary" onclick="compareZones()">Compare</button>
        </div>
      </div>
    </div>

    <!-- ══════════════ PAGE: Cloudflare One (Account) ══════════════ -->
    <div id="page-one" class="hidden">
      <div class="card hidden" id="acct-card">
        <h2>Cloudflare One — Zero Trust <span class="sub">— Access, Gateway, Tunnels, Devices, DLP — account-level, zone-independent</span></h2>
        <div class="form-row" style="margin-bottom:10px">
          <div class="field" style="max-width:420px">
            <label>Account</label>
            <input type="text" id="acct-name-display" readonly value="—" placeholder="detected after Load Zones">
          </div>
          <button class="btn btn-primary" id="acct-fetch-btn" onclick="fetchConfigs('account')">Fetch &amp; Save First Version</button>
        </div>
        <div class="muted" id="acct-note" style="font-size:12.5px">
          The current configuration loads automatically when you open this page. Auto-checked every 5 minutes — every change becomes a version attributed to the admin who made it.
          <details style="margin-top:6px">
            <summary style="cursor:pointer;font-size:12.5px;color:var(--cf-blue);font-weight:600">What&rsquo;s included?</summary>
            <div style="margin-top:6px;line-height:1.7">
              <b>Zero Trust only</b>, account-level and never mixed with WAF: Access apps / policies / groups / service tokens, Identity Providers, Gateway configuration / lists / locations / rules, tunnels + routes + virtual networks, device posture &amp; settings, risk scoring and DLP profiles.
            </div>
          </details>
        </div>
        <div id="acct-progress-area" class="hidden" style="margin-top:12px">
          <div style="font-size:13px;color:var(--cf-muted)" id="acct-progress-label">Fetching...</div>
          <div class="progress-bar"><div class="progress-fill" id="acct-progress-fill" style="width:0%"></div></div>
          <div class="status-chips" id="acct-status-chips"></div>
        </div>
      </div>
      <div class="card" id="acct-empty-card">
        <h2>Cloudflare One — Zero Trust</h2>
        <div class="muted" style="padding:8px 0 14px 0;font-size:13.5px;line-height:1.7">
          Connect from the <b>Settings</b> page — your account is detected automatically and this page activates.
          No zone selection needed: Zero Trust is account-level configuration with its own version history, change detection and restore.
        </div>
      </div>

      <div class="card hidden" id="acct-results-card">
        <h2>Account Results</h2>
        <div id="acct-drift-banner" class="hidden"></div>
        <div class="results-toolbar">
          <button class="btn btn-secondary" onclick="copyResults('account')">Copy JSON</button>
          <button class="btn btn-outline" onclick="downloadResults('account')">Download JSON</button>
          <button class="btn btn-outline" onclick="saveVersion('account')">Save as Version</button>
          <span class="info" id="acct-results-info"></span>
        </div>
        <div class="tab-bar" id="acct-tab-bar"></div>
        <div id="acct-tab-panels"></div>
      </div>

      <div class="card" id="acct-versions-card">
        <h2>Zero Trust Version Snapshots <span class="sub">— the newest version is the current baseline; restore any version to roll back to it</span></h2>
        <div class="results-toolbar">
          <button class="btn btn-outline" onclick="loadVersions('account')">Refresh</button>
          <button class="btn btn-primary" id="acct-check-btn" onclick="checkChanges('account')">Check for changes</button>
          <button class="btn btn-secondary" id="acct-named-btn" onclick="saveNamedSnapshot('account')">Save Named Snapshot</button>
          <button class="btn btn-outline" onclick="toggleBlock('acct-ver-filters', this)">Filters &#9662;</button>
          <button class="btn btn-outline" onclick="toggleBlock('acct-compare-bar', this)">Compare versions &#9662;</button>
          <span class="info" id="acct-versions-info"></span>
        </div>
        <div class="filter-bar hidden" id="acct-ver-filters">
          <div class="field" style="min-width:130px">
            <label>Trigger</label>
            <select id="acct-ver-filter-trigger" onchange="renderVersions('account')">
              <option value="">All</option>
              <option value="manual">Manual</option>
              <option value="scheduled">Scheduled</option>
              <option value="pre_rollback">Pre-rollback</option>
              <option value="rollback">Restore</option>
            </select>
          </div>
          <div class="field" style="min-width:110px">
            <label>Kind</label>
            <select id="acct-ver-filter-kind" onchange="renderVersions('account')">
              <option value="">All</option>
              <option value="named">Named</option>
              <option value="full">Full</option>
              <option value="delta">Delta</option>
            </select>
          </div>
          <div class="field" style="flex:1;min-width:180px">
            <label>Search</label>
            <input type="text" id="acct-ver-filter-search" placeholder="version, description, actor…" oninput="renderVersions('account')">
          </div>
          <button class="btn btn-outline" onclick="resetVerFilters('account')">Reset filters</button>
        </div>
        <table>
          <thead>
            <tr><th>Version</th><th>Object changes</th><th>Date</th><th>Created by</th><th>Description</th><th>Kind</th><th>Actions</th></tr>
          </thead>
          <tbody id="acct-versions-tbody"><tr><td colspan="7" class="muted" style="padding:14px">Loading…</td></tr></tbody>
        </table>
        <div class="results-toolbar hidden" style="margin-top:14px" id="acct-compare-bar">
          <select id="acct-cmp-a" style="padding:8px;border:1px solid var(--cf-border);border-radius:6px;font-size:13px;min-width:220px"></select>
          <span class="muted">vs</span>
          <select id="acct-cmp-b" style="padding:8px;border:1px solid var(--cf-border);border-radius:6px;font-size:13px;min-width:220px"></select>
          <button class="btn btn-outline" onclick="compareVersions('account')">Compare versions</button>
        </div>
      </div>
    </div>

    <!-- Diff (shared display area) -->
    <div class="card hidden" id="diff-card">
      <h2 id="diff-title">Configuration Diff</h2>
      <div id="diff-output"></div>
    </div>

    <!-- ══════════════ PAGE: Audit Log ══════════════ -->
    <div id="page-audit" class="hidden">
      <div class="card" id="audit-card">
        <h2>Audit Log <span class="sub">— append-only change history</span></h2>
        <div class="filter-bar">
          <div class="field" style="min-width:200px">
            <label>Target</label>
            <select id="audit-zone-select"><option value="">All targets</option></select>
          </div>
          <div class="field">
            <label>Action</label>
            <select id="audit-action"></select>
          </div>
          <div class="field">
            <label>Actor</label>
            <input type="text" id="audit-actor" placeholder="email">
          </div>
          <div class="field">
            <label>From</label>
            <input type="date" id="audit-from">
          </div>
          <div class="field">
            <label>To</label>
            <input type="date" id="audit-to">
          </div>
          <button class="btn btn-primary" onclick="loadAudit(true)">Apply</button>
          <button class="btn btn-outline" onclick="resetAuditFilters()">Reset</button>
        </div>
        <table>
          <thead>
            <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Details</th></tr>
          </thead>
          <tbody id="audit-tbody"><tr><td colspan="6" class="muted">Loading…</td></tr></tbody>
        </table>
        <div class="audit-nav">
          <button class="btn btn-outline" id="audit-prev" onclick="auditPrev()">Prev</button>
          <button class="btn btn-outline" id="audit-next" onclick="auditNext()">Next</button>
          <span id="audit-nav"></span>
        </div>
      </div>
    </div>

    <!-- ══════════════ PAGE: Reference (settings catalog) ══════════════ -->
    <div id="page-reference" class="hidden">
      <div class="card">
        <h2>Reference — captured settings <span class="sub">— every endpoint this manager versions, per product</span></h2>
        <div class="muted" style="font-size:13px;line-height:1.7;margin-bottom:12px">
          <b>AppSec</b> covers zone-level WAF, DDoS, Bot, API Shield, TLS, CDN/caching and DNS, plus account-level WAF.
          <b>Cloudflare One</b> covers pure Zero Trust (Access, Gateway, tunnels, devices, DLP) at the account level.
          <span class="chip chip-ok">Restorable</span> the restore engine can write it back &nbsp;
          <span class="chip chip-skip">View-only</span> fetched for history/diff context, never written back.
          Runtime data (tunnel status, key rotation state, match counters, timestamps) is captured but never triggers versions.
        </div>
        <div class="form-row" style="margin-bottom:14px">
          <div class="field" style="max-width:380px">
            <label>Search settings</label>
            <input type="text" id="ref-search" placeholder="e.g. cache, access, TLS, DNS…" oninput="renderReference()">
          </div>
          <span class="info" id="ref-count" style="font-size:13px;color:var(--cf-muted);margin-left:auto"></span>
        </div>
        <div id="ref-body"></div>
      </div>
    </div>
  </div>

  <!-- Restore modal (shared) -->
  <div class="modal-overlay hidden" id="modal-overlay" onclick="if(event.target===this)closeModal()">
    <div class="modal" id="modal-body"></div>
  </div>

  <script>
    // ── State ──────────────────────────────────────────────────────────────
    let allZones = [];
    let categories = [];
    let auditOffset = 0;
    let currentPage = 'appsec';
    let pendingZone = null;      // zone to restore from a saved session
    const AUDIT_PAGE = 25;
    const SESSION_KEY = 'cf_config_session';

    // Per-scope element ids and state. 'zone' = the AppSec (Zone) page,
    // 'account' = the Cloudflare One (Account) page.
    const SCOPES = {
      zone: {
        page: 'page-appsec',
        resultsCard: 'zone-results-card', tabBar: 'zone-tab-bar', tabPanels: 'zone-tab-panels',
        resultsInfo: 'zone-results-info', driftBanner: 'zone-drift-banner',
        versionsCard: 'zone-versions-card', versionsTbody: 'zone-versions-tbody', versionsInfo: 'zone-versions-info',
        filterTrigger: 'zone-ver-filter-trigger', filterKind: 'zone-ver-filter-kind', filterSearch: 'zone-ver-filter-search',
        cmpA: 'zone-cmp-a', cmpB: 'zone-cmp-b',
        fetchBtn: 'zone-fetch-btn', checkBtn: 'zone-check-btn', namedBtn: 'zone-named-btn',
        progressArea: 'zone-progress-area', progressLabel: 'zone-progress-label', progressFill: 'zone-progress-fill', statusChips: 'zone-status-chips',
        state: { result: null, versions: [], savedState: null, liveMatches: null, lastAutoFetch: 0 },
      },
      account: {
        page: 'page-one',
        resultsCard: 'acct-results-card', tabBar: 'acct-tab-bar', tabPanels: 'acct-tab-panels',
        resultsInfo: 'acct-results-info', driftBanner: 'acct-drift-banner',
        versionsCard: 'acct-versions-card', versionsTbody: 'acct-versions-tbody', versionsInfo: 'acct-versions-info',
        filterTrigger: 'acct-ver-filter-trigger', filterKind: 'acct-ver-filter-kind', filterSearch: 'acct-ver-filter-search',
        cmpA: 'acct-cmp-a', cmpB: 'acct-cmp-b',
        fetchBtn: 'acct-fetch-btn', checkBtn: 'acct-check-btn', namedBtn: 'acct-named-btn',
        progressArea: 'acct-progress-area', progressLabel: 'acct-progress-label', progressFill: 'acct-progress-fill', statusChips: 'acct-status-chips',
        state: { result: null, versions: [], savedState: null, liveMatches: null, lastAutoFetch: 0 },
      },
    };

    const $ = id => document.getElementById(id);

    // ── Friendly audit labels ─────────────────────────────────────────────
    const AUDIT_LABELS = {
      'snapshot.create': 'Version saved',
      'snapshot.view': 'Version viewed',
      'snapshot.delete': 'Version deleted',
      'snapshot.diff': 'Version diffed',
      'rollback.dry_run': 'Restore previewed',
      'rollback.execute': 'Restore executed',
      'retention.prune': 'Retention prune',
      'auth.denied': 'Sign-in denied',
    };
    function auditLabel(action) { return AUDIT_LABELS[action] || action; }

    // ── Session persistence (browser localStorage only) ─────────────────────
    function loadSession() {
      try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; }
    }
    function saveSession() {
      try {
        localStorage.setItem(SESSION_KEY, JSON.stringify({
          token: $('api-token').value.trim(),
          accountId: $('account-id').value.trim(),
          zone: $('zone-select').value || '',
          page: currentPage,
        }));
      } catch (e) { /* storage unavailable */ }
      updateSessionPill();
    }
    function clearSession() {
      if (!confirm('Clear the saved session (token and settings) from this device?')) return;
      try { localStorage.removeItem(SESSION_KEY); } catch (e) {}
      location.reload();
    }
    function updateSessionPill() {
      const pill = $('session-pill');
      const btn = $('clear-session-btn');
      const sess = loadSession();
      const has = !!(sess && sess.token);
      if (pill) { pill.textContent = 'Session saved on this device'; pill.style.display = has ? '' : 'none'; }
      if (btn) btn.style.display = has ? '' : 'none';
    }
    function restoreSession() {
      updateSessionPill();
      const sess = loadSession();
      if (!sess || !sess.token) { showPage('settings', true); return; }
      $('api-token').value = sess.token;
      if (sess.accountId) $('account-id').value = sess.accountId;
      pendingZone = sess.zone || null;
      showPage(['overview', 'appsec', 'one', 'audit', 'reference', 'settings'].includes(sess.page) ? sess.page : 'overview', true);
      loadZones(); // auto-connect with the saved token
    }

    // ── Pages ─────────────────────────────────────────────────────────────
    function showPage(name, skipSave) {
      currentPage = name;
      const pages = { overview: 'page-overview', appsec: 'page-appsec', one: 'page-one', audit: 'page-audit', reference: 'page-reference', settings: 'page-settings' };
      for (const [key, id] of Object.entries(pages)) {
        const el = $(id);
        if (el) el.classList.toggle('hidden', key !== name);
        const nav = $('nav-' + key);
        if (nav) nav.classList.toggle('active', key === name);
      }
      // the More menu link stays highlighted while any of its subpages is open
      const more = $('nav-more');
      if (more) more.classList.toggle('active', ['audit', 'reference', 'settings'].includes(name));
      if (!skipSave) saveSession();
      if (name === 'overview') loadOverview();
      if (name === 'audit') loadAudit(true);
      if (name === 'reference') renderReference();
      if (name === 'appsec') autoOpenScope('zone');
      if (name === 'one') autoOpenScope('account');
    }

    // ── More menu (overflow nav) ───────────────────────────────────────────
    function toggleMoreMenu(ev) { if (ev) ev.stopPropagation(); const m = $('more-menu'); if (m) m.classList.toggle('hidden'); }
    function closeMoreMenu() { const m = $('more-menu'); if (m) m.classList.add('hidden'); }
    document.addEventListener('click', function (e) { if (!(e.target.closest && e.target.closest('.nav-more'))) closeMoreMenu(); });

    // Show/hide an optional UI block (filters, compare bar) and flip the
    // trigger button's arrow.
    function toggleBlock(id, btn) {
      const el = $(id);
      if (!el) return;
      el.classList.toggle('hidden');
      if (btn) btn.innerHTML = btn.innerHTML.replace(/\s[&#9662;&#9652;]+;?/g, el.classList.contains('hidden') ? ' &#9662;' : ' &#9652;');
    }

    // ── Init ───────────────────────────────────────────────────────────────
    async function init() {
      const res = await fetch('/api/categories');
      categories = await res.json();
      const grid = $('cat-grid');
      const appsecCats = categories.filter(c => (c.product || 'appsec') === 'appsec');
      appsecCats.forEach(cat => {
        const card = document.createElement('div');
        card.className = 'cat-card selected';
        card.dataset.key = cat.key;
        const isAcctWaf = cat.key === 'account_sec';
        card.innerHTML = '<input type="checkbox" checked value="' + cat.key + '">'
          + '<div class="cat-card-label">' + escHtml(cat.label) + '</div>'
          + (isAcctWaf ? '<div class="muted" style="font-size:11.5px;margin-top:3px">account-level — part of the AppSec product</div>' : '');
        card.addEventListener('click', () => toggleCat(card));
        grid.appendChild(card);
      });

      const ccs = $('compare-cat-select');
      categories.filter(c => (c.product || 'appsec') === 'appsec').forEach(cat => {
        const o = document.createElement('option');
        o.value = cat.key; o.textContent = cat.label;
        ccs.appendChild(o);
      });

      const actions = ['', 'snapshot.create', 'snapshot.view', 'snapshot.delete', 'snapshot.diff',
        'rollback.dry_run', 'rollback.execute', 'retention.prune', 'auth.denied'];
      const asel = $('audit-action');
      actions.forEach(a => {
        const o = document.createElement('option');
        o.value = a; o.textContent = a ? auditLabel(a) : 'All actions';
        asel.appendChild(o);
      });

      loadWhoami();
      loadOverview();
      restoreSession();
    }

    async function loadWhoami() {
      const pill = $('user-pill');
      try {
        const r = await fetch('/api/whoami').then(r => r.json());
        if (r.authenticated) {
          pill.textContent = 'Signed in as ' + r.actor;
        } else {
          pill.textContent = 'Anonymous — Access not configured';
          pill.classList.add('pill-warn');
          pill.title = 'Set the ACCESS_TEAM_DOMAIN and ACCESS_AUD secrets and protect this app with a Cloudflare Access policy so every action is attributed to a named user.';
        }
      } catch (e) {
        pill.textContent = 'Authentication unavailable';
      }
    }

    // ── Alerts & helpers ───────────────────────────────────────────────────
    function showAlert(msg, type) {
      type = type || 'danger';
      const c = $('alert-container');
      c.innerHTML = '<div class="alert alert-' + type + '">' + msg + '</div>';
      if (type === 'success') setTimeout(() => { c.innerHTML = ''; }, 4000);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    function escHtml(s) {
      return String(s === undefined || s === null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }
    function catLabel(key) {
      const c = categories.find(x => x.key === key);
      return c ? c.label : key;
    }
    function scopeTargetId(scope) {
      if (scope === 'account') return $('account-id').value.trim();
      return $('zone-select').value || '';
    }
    function scopeTargetName(scope) {
      if (scope === 'account') return 'Account — Cloudflare One';
      const sel = $('zone-select');
      const o = sel.options && sel.options[sel.selectedIndex];
      return o ? o.textContent : '';
    }
    function scopeForVersion(id) {
      if (SCOPES.zone.state.versions.some(v => v.id === id)) return 'zone';
      if (SCOPES.account.state.versions.some(v => v.id === id)) return 'account';
      return currentPage === 'one' ? 'account' : 'zone';
    }

    function api(method, path, body) {
      const headers = {};
      const token = $('api-token').value.trim();
      if (token) headers['Authorization'] = token;
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      return fetch(path, {
        method: method,
        headers: headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      }).then(async res => {
        let data = {};
        try { data = await res.json(); } catch (e) {}
        if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
        return data;
      });
    }

    // ── Zones & account discovery (shared) ──────────────────────────────────
    function populateZoneSelect() {
      const sel = $('zone-select');
      const prev = pendingZone || sel.value;
      sel.innerHTML = '';
      allZones.forEach(z => { const o = document.createElement('option'); o.value = z.id; o.textContent = z.name; sel.appendChild(o); });
      if (prev) {
        try { for (const o of sel.options) if (o.value === prev) { sel.value = prev; break; } } catch (e) { /* shim */ }
      }
      pendingZone = null;
      zoneChanged();
    }

    function zoneChanged() {
      const note = $('scope-note');
      if (note) note.innerHTML = '<b>AppSec</b> — WAF, DDoS, Bot, API Shield, TLS, CDN and DNS for this zone' + ($('account-id').value.trim() ? ' + account-level WAF' : '') + '. Auto-checked every 5 min.';
      saveSession();
      SCOPES.zone.state.liveMatches = null; // different target — current/live status unknown
      loadVersions('zone');
    }

    function onAccountIdChange() {
      updateAcctCard();
      saveSession();
      SCOPES.account.state.liveMatches = null;
      loadVersions('account');
    }

    function updateAcctCard() {
      const has = !!$('account-id').value.trim();
      $('acct-card').classList.toggle('hidden', !has);
      $('acct-empty-card').classList.toggle('hidden', has);
    }

    function updateSettingsStatus() {
      const el = $('settings-status');
      if (!el) return;
      if (!allZones.length) { el.innerHTML = 'Not connected — paste your API token and click <b>Connect</b>.'; return; }
      const acct = $('account-id').value.trim();
      el.innerHTML = '\u2714 Connected: ' + allZones.length + ' zone(s)' + (acct ? ' + Account (Cloudflare One)' : '') +
        '. Operation pages: <b>AppSec</b> (zone-level) and <b>Cloudflare One</b> (account-level).';
    }

    async function autoDiscoverAccount() {
      if ($('account-id').value.trim()) { updateAcctCard(); return; }
      try {
        const res = await fetch('/api/accounts', { headers: { 'Authorization': $('api-token').value.trim() } });
        const data = await res.json();
        if (data.success && data.result && data.result.length) {
          $('account-id').value = data.result[0].id;
          const disp = $('acct-name-display');
          if (disp) disp.value = (data.result[0].name || data.result[0].id) + ' (' + data.result[0].id + ')';
          updateAcctCard();
          loadOverview();
          loadVersions('account');
          showAlert('Account detected: ' + (data.result[0].name || data.result[0].id) + ' — the Cloudflare One page is now active', 'success');
        }
      } catch (e) { /* not fatal — user can still enter it manually */ }
    }

    async function loadZones() {
      const token = $('api-token').value.trim();
      if (!token) { showAlert('Enter your API token'); return; }
      const btn = $('load-zones-btn');
      btn.disabled = true; btn.textContent = 'Loading…';
      try {
        const res = await fetch('/api/zones', { headers: { 'Authorization': token } });
        const data = await res.json();
        if (!data.success) throw new Error((data.errors && data.errors[0] && data.errors[0].message) || 'Unknown error');
        allZones = data.result;
        if (!allZones.length) { showAlert('No zones found for this token', 'warning'); return; }

        populateZoneSelect();

        const csel = $('compare-zone-select');
        csel.innerHTML = '';
        allZones.forEach(z => { const o = document.createElement('option'); o.value = z.id; o.textContent = z.name; csel.appendChild(o); });

        const azsel = $('audit-zone-select');
        azsel.innerHTML = '<option value="">All targets</option>';
        const acct = $('account-id').value.trim();
        if (acct) {
          const ao = document.createElement('option');
          ao.value = acct; ao.textContent = 'Account — Cloudflare One';
          azsel.appendChild(ao);
        }
        allZones.forEach(z => { const o = document.createElement('option'); o.value = z.id; o.textContent = z.name; azsel.appendChild(o); });

        $('zone-card').classList.remove('hidden');
        $('compare-btn').style.display = allZones.length > 1 ? '' : 'none';
        saveSession();
        updateAcctCard();
        loadOverview();
        updateSettingsStatus();
        showAlert('Connected — ' + allZones.length + ' zone(s)' + (acct ? ' + Account (Cloudflare One)' : '') + '. The overview shows drift status; AppSec and Cloudflare One pages are ready.', 'success');
        if (currentPage === 'settings') showPage('overview');
        autoDiscoverAccount();
      } catch (e) { showAlert('Error: ' + e.message); }
      finally { btn.disabled = false; btn.textContent = 'Connect'; }
    }

    // ── Targets Overview (shared drift dashboard) ──────────────────────────
    function timeAgo(iso) {
      if (!iso) return '—';
      const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
      if (s < 0 || isNaN(s)) return '—';
      if (s < 60) return 'just now';
      if (s < 3600) return Math.floor(s / 60) + 'm ago';
      if (s < 86400) return Math.floor(s / 3600) + 'h ago';
      return Math.floor(s / 86400) + 'd ago';
    }

    function friendlyCheckResult(r) {
      if (!r) return 'never checked';
      if (r === 'no_change' || r === 'no_change (audit)') return 'no changes';
      if (r.indexOf('changed: v') === 0) return 'drift recorded \u2192 ' + r.slice(9);
      if (r === 'initial version') return 'baseline saved';
      if (r === 'named snapshot saved') return 'named snapshot';
      if (r.indexOf('error') === 0) return r.slice(0, 70);
      return r;
    }

    // ── Reference page: render the settings catalog from /api/categories ──
    // categories is loaded once at init and carries per-endpoint desc, path
    // template, scope, product and restorability (computed by the worker from
    // the rollback engine's classification — single source of truth).
    function renderReference() {
      const body = $('ref-body');
      const countEl = $('ref-count');
      if (!body) return;
      const q = ($('ref-search').value || '').trim().toLowerCase();
      const products = [
        { key: 'appsec', title: 'Cloudflare AppSec', sub: 'zone-level WAF / DDoS / Bot / API Shield + TLS / CDN / DNS, plus account-level WAF' },
        { key: 'one',    title: 'Cloudflare One — Zero Trust', sub: 'Access, Gateway, tunnels, devices, DLP — account-level' },
      ];
      let total = 0, shown = 0;
      let html = '';
      for (const prod of products) {
        const cats = categories.filter(c => (c.product || 'appsec') === prod.key);
        let prodHtml = '';
        for (const cat of cats) {
          const eps = (cat.endpoints || []).filter(ep =>
            !q || ep.name.toLowerCase().includes(q) ||
            (ep.desc || '').toLowerCase().includes(q) ||
            cat.label.toLowerCase().includes(q) ||
            (ep.restore_note || '').toLowerCase().includes(q));
          total += (cat.endpoints || []).length;
          shown += eps.length;
          if (!eps.length) continue;
          let rows = '';
          for (const ep of eps) {
            rows += '<tr>'
              + '<td style="white-space:nowrap"><span class="mono" style="font-weight:600">' + escHtml(ep.name) + '</span>'
              + (ep.scope === 'account' ? '<br><span class="badge badge-acct" style="margin-top:3px">account</span>' : '')
              + '<div class="muted mono" style="margin-top:3px;white-space:normal;word-break:break-all">' + escHtml(ep.path) + '</div></td>'
              + '<td style="font-size:12.5px;line-height:1.6">' + escHtml(ep.desc || '') + '</td>'
              + '<td style="white-space:nowrap">'
              + (ep.restorable
                ? '<span class="chip chip-ok">Restorable</span>'
                  + '<div class="muted" style="font-size:11.5px;margin-top:4px;white-space:normal;max-width:220px">' + escHtml(ep.restore_note || '') + '</div>'
                : '<span class="chip chip-skip">View-only</span>')
              + '</td></tr>';
          }
          prodHtml += '<div class="card" style="box-shadow:none;border:1px solid var(--cf-border);margin-top:12px">'
            + '<h2 style="margin-bottom:8px">' + escHtml(cat.label) + ' <span class="sub">— ' + eps.length + ' setting' + (eps.length === 1 ? '' : 's') + '</span></h2>'
            + '<table><thead><tr><th style="width:220px">Setting</th><th>What it controls</th><th style="width:140px">Restore</th></tr></thead><tbody>'
            + rows + '</tbody></table></div>';
        }
        if (prodHtml) {
          html += '<div style="margin-top:20px">'
            + '<h3 style="font-size:16px;color:var(--cf-blue);border-bottom:2px solid var(--cf-orange);display:inline-block;padding-bottom:4px">' + escHtml(prod.title) + '</h3>'
            + '<div class="muted" style="font-size:12.5px;margin:6px 0 2px 0">' + escHtml(prod.sub) + '</div>'
            + prodHtml + '</div>';
        }
      }
      if (q && !shown) {
        html = '<div class="diff-empty">No settings match &ldquo;' + escHtml(q) + '&rdquo;.</div>';
      }
      body.innerHTML = html;
      if (countEl) countEl.textContent = q ? shown + ' of ' + total + ' settings' : total + ' settings';
    }

    async function loadOverview() {
      const card = $('overview-card');
      const empty = $('overview-empty-card');
      const showEmpty = (html, actionsHtml) => {
        if (empty) {
          $('overview-empty-body').innerHTML = html;
          $('overview-empty-actions').innerHTML = actionsHtml || '';
          empty.classList.remove('hidden');
        }
        card.classList.add('hidden');
      };
      if (!$('api-token').value.trim()) {
        showEmpty('Not connected yet. Open <b>Settings</b> to paste your Cloudflare API token and connect — your zones and the Cloudflare One account are detected automatically.',
          '<button class="btn btn-primary" onclick="showPage(\\'settings\\')">Open Settings</button>');
        return;
      }
      try {
        const r = await api('GET', '/api/tracked-zones');
        const rows = r.tracked || [];
        if (!rows.length) {
          showEmpty('Connected, but no versions yet. Open <b>AppSec</b> or <b>Cloudflare One</b>, fetch a configuration and save the first baseline — after that, changes are captured automatically every 5 minutes.',
            '<button class="btn btn-primary" onclick="showPage(\\'appsec\\')">Open AppSec</button> ' +
            '<button class="btn btn-secondary" onclick="showPage(\\'one\\')">Open Cloudflare One</button>');
          return;
        }
        if (empty) empty.classList.add('hidden');
        card.classList.remove('hidden');
        const tbody = $('overview-tbody');
        tbody.innerHTML = '';
        rows.forEach(z => {
          const isAcct = z.scope === 'account';
          const res = friendlyCheckResult(z.last_check_result);
          const resCls = /^error/i.test(z.last_check_result || '') ? 'err' : (/^changed/i.test(z.last_check_result || '') ? 'warn' : 'ok');
          const tr = document.createElement('tr');
          tr.innerHTML =
            '<td><b>' + escHtml(z.zone_name || '') + '</b>' + (isAcct ? ' <span class="badge badge-acct" title="Account-level configuration (Cloudflare One)">account</span>' : ' <span class="badge badge-changed" title="Zone-level configuration">zone</span>') + '</td>' +
            '<td>' + (isAcct ? 'Account' : 'Zone') + '</td>' +
            '<td>v' + (z.last_version || '—') + '</td>' +
            '<td>' + (z.version_count || 0) + '</td>' +
            '<td title="' + escHtml(z.last_checked_at || '') + '">' + timeAgo(z.last_checked_at) + '</td>' +
            '<td><span class="chip chip-' + resCls + '" title="' + escHtml(z.last_check_result || '') + '">' + escHtml(res) + '</span></td>' +
            '<td class="row-actions">' +
              '<button class="link-btn" onclick="checkNow(\\'' + z.zone_id + '\\')">Check now</button>' +
              '<button class="link-btn" onclick="selectTarget(\\'' + z.zone_id + '\\',' + (isAcct ? 'true' : 'false') + ')">Open</button>' +
            '</td>';
          tbody.appendChild(tr);
        });
        $('overview-info').textContent = rows.length + ' target(s) tracked';
      } catch (e) { card.classList.add('hidden'); }
    }

    async function checkNow(targetId) {
      if (!$('api-token').value.trim()) { showAlert('Checking requires your Cloudflare API token'); return; }
      try {
        const r = await api('POST', '/api/versions/check', { zone_id: targetId });
        if (r.no_change) showAlert('No changes since v' + r.version, 'success');
        else showAlert('Change recorded as v' + r.version + (r.change_summary ? ' — ' + r.change_summary.endpoints + ' endpoint(s)' : ''), 'success');
        loadOverview();
        loadVersions('zone');
        loadVersions('account');
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    function selectTarget(targetId, isAccount) {
      if (isAccount) {
        showPage('one');
        if (!$('account-id').value.trim()) $('account-id').value = targetId;
        updateAcctCard();
        loadVersions('account');
        $('acct-versions-card').scrollIntoView({ behavior: 'smooth' });
      } else {
        showPage('appsec');
        const sel = $('zone-select');
        try {
          for (const o of sel.options) if (o.value === targetId) { sel.value = targetId; break; }
        } catch (e) { /* shim */ }
        zoneChanged();
        $('zone-versions-card').scrollIntoView({ behavior: 'smooth' });
      }
    }

    // ── Category toggles (zone page) ────────────────────────────────────────
    function toggleCat(card) {
      const cb = card.querySelector('input');
      cb.checked = !cb.checked;
      card.classList.toggle('selected', cb.checked);
      const allChecked = document.querySelectorAll('.cat-card.selected').length === document.querySelectorAll('.cat-card').length;
      $('cat-all').checked = allChecked;
    }
    function toggleAllCats(checked) {
      document.querySelectorAll('.cat-card').forEach(c => {
        c.querySelector('input').checked = checked;
        c.classList.toggle('selected', checked);
      });
    }
    function selectedCats() {
      return Array.from(document.querySelectorAll('.cat-card.selected')).map(c => c.dataset.key);
    }

    // ── Fetch (scoped) ─────────────────────────────────────────────────────
    // Opening a product page auto-loads the version history and refreshes the
    // current live configuration (throttled to once per minute per target).
    // The page therefore always opens on the current state: the latest version
    // is badged "current" when it matches live, and the drift banner explains
    // any unsaved difference. Nothing is ever auto-saved — saving stays explicit.
    async function autoOpenScope(scope) {
      const S = SCOPES[scope];
      await loadVersions(scope);
      if (!$('api-token').value.trim()) return;
      const targetId = scopeTargetId(scope);
      if (!targetId) return;
      if (Date.now() - (S.state.lastAutoFetch || 0) < 60000) return;
      S.state.lastAutoFetch = Date.now();
      fetchConfigs(scope); // async — shows results + drift banner (preview only)
    }

    async function fetchConfigs(scope) {
      const S = SCOPES[scope];
      const token = $('api-token').value.trim();
      const targetId = scopeTargetId(scope);
      if (!token) { showAlert('Enter API token'); return; }
      if (!targetId) { showAlert(scope === 'account' ? 'Account ID missing — click Load Zones to auto-detect it' : 'Select a zone'); return; }
      const cats = selectedCats();
      if (scope === 'zone' && !cats.length) { showAlert('Select at least one category', 'warning'); return; }

      const btn = $(S.fetchBtn);
      btn.disabled = true; btn.textContent = 'Fetching…';
      $(S.progressArea).classList.remove('hidden');
      $(S.statusChips).innerHTML = '';
      $(S.progressFill).style.width = '0%';
      $(S.progressLabel).textContent = 'Fetching…';

      try {
        let res;
        if (scope === 'account') {
          res = await fetch('/api/account-configs/' + targetId, {
            headers: { 'Authorization': token }
          });
        } else {
          const qs = new URLSearchParams({ cats: cats.join(',') });
          if ($('account-id').value.trim()) qs.set('accountId', $('account-id').value.trim());
          res = await fetch('/api/configs/' + targetId + '?' + qs, {
            headers: { 'Authorization': token }
          });
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Fetch failed');

        S.state.result = data;
        S.state.savedState = false; // unsaved until saved or proven identical
        const resultCats = (data._meta && data._meta.categories_requested) ||
          Object.keys(data).filter(k => k !== '_meta');
        renderResults(data, resultCats, scope);
        $(S.progressFill).style.width = '100%';
        $(S.progressLabel).textContent = 'Done';

        const chips = $(S.statusChips);
        (data._meta && data._meta.fetched_endpoints ? data._meta.fetched_endpoints : []).forEach(ep => {
          const chip = document.createElement('span');
          chip.className = 'chip chip-' + (ep.status === 'ok' ? 'ok' : ep.status === 'skipped' ? 'skip' : 'err');
          chip.title = ep.path || '';
          chip.textContent = ep.name;
          chips.appendChild(chip);
        });
        await loadVersions(scope);
        await driftPreview(scope); // "differs from vN — save / review" banner
      } catch (e) { showAlert('Error: ' + e.message); }
      finally { btn.disabled = false; updatePrimaryButton(scope); }
    }

    // Post-fetch drift banner: compares the fetched state against the latest
    // version WITHOUT saving (preview mode) and offers a one-click save.
    async function driftPreview(scope) {
      const S = SCOPES[scope];
      const el = $(S.driftBanner);
      const targetId = scopeTargetId(scope);
      if (!el || !targetId) { if (el) el.classList.add('hidden'); return; }
      try {
        const r = await api('POST', '/api/versions/check', { zone_id: targetId, preview: true });
        if (r.no_change) {
          S.state.savedState = true;
          S.state.liveMatches = true;
          el.innerHTML = '<div class="alert alert-success">\u2714 Matches <b>v' + r.version + '</b> — the fetched configuration is identical to the latest version. Nothing to save.</div>';
          el.classList.remove('hidden');
        } else if (r.would_create) {
          const s = r.change_summary || {};
          S.state.liveMatches = false;
          el.innerHTML = '<div class="alert alert-warning"><b>\u26a0 Fetched state differs from v' + r.version + '</b> — +' +
            ((s.item_added || 0) + (s.added || 0)) + ' added, &minus;' + (s.item_removed || 0) + ' removed, ~' + (s.item_changed || 0) + ' changed (' +
            (s.endpoints || 0) + ' endpoint(s)). ' +
            '<button class="btn btn-primary" style="margin-left:8px" onclick="saveVersion(\\'' + scope + '\\')">Save as new version</button>' +
            '<button class="btn btn-outline" style="margin-left:6px" onclick="driftReview(\\'' + scope + '\\')">Review changes</button></div>';
          el.classList.remove('hidden');
        }
        renderVersions(scope); // refresh the current/latest badge on the newest row
      } catch (e) {
        // no baseline for this target (404) → prompt to save the first one
        if (!S.state.versions.length) {
          el.innerHTML = '<div class="alert alert-warning">No version exists for this target yet — this fetch can become the first baseline. ' +
            '<button class="btn btn-primary" style="margin-left:8px" onclick="saveVersion(\\'' + scope + '\\')">Save the first version</button></div>';
          el.classList.remove('hidden');
        } else {
          el.classList.add('hidden'); // transient error — don't nag
        }
      }
      updateResultsInfo(scope);
    }

    function driftReview(scope) {
      const S = SCOPES[scope];
      const latest = S.state.versions[0];
      if (!latest) { showAlert('No version to compare against yet'); return; }
      diffVersionLive(latest.id);
    }

    function updateResultsInfo(scope) {
      const S = SCOPES[scope];
      const info = $(S.resultsInfo);
      if (!info || !S.state.result) return;
      const m = S.state.result._meta || {};
      const base = (m.total_fetched !== undefined ? m.total_fetched : '?') + ' fetched, ' +
        (m.total_skipped !== undefined ? m.total_skipped : '?') + ' skipped';
      info.textContent = base + (S.state.savedState === false ? ' \u00b7 not saved yet' : '');
    }

    // ── Render results as tabs (scoped) ────────────────────────────────────
    function renderResults(data, cats, scope) {
      const S = SCOPES[scope];
      const tabBar = $(S.tabBar);
      const panels = $(S.tabPanels);
      tabBar.innerHTML = ''; panels.innerHTML = '';

      const catMeta = {};
      categories.forEach(c => { catMeta[c.key] = c.label; });

      let firstTab = null;
      cats.forEach(catKey => {
        const catData = data[catKey];
        if (!catData) return;
        const tab = document.createElement('div');
        tab.className = 'tab' + (firstTab === null ? ' active' : '');
        tab.textContent = catMeta[catKey] || catKey;
        tab.dataset.cat = catKey;
        tab.onclick = () => activateTab(scope, catKey);
        tabBar.appendChild(tab);

        const panel = document.createElement('div');
        panel.className = 'tab-panel' + (firstTab === null ? ' active' : '');
        panel.id = 'panel-' + scope + '-' + catKey;
        panel.innerHTML = '<pre>' + escHtml(JSON.stringify(catData, null, 2)) + '</pre>';
        panels.appendChild(panel);
        if (firstTab === null) firstTab = catKey;
      });

      if (data._meta) {
        const tab = document.createElement('div');
        tab.className = 'tab'; tab.textContent = '_meta'; tab.dataset.cat = '_meta';
        tab.onclick = () => activateTab(scope, '_meta');
        tabBar.appendChild(tab);
        const panel = document.createElement('div');
        panel.className = 'tab-panel'; panel.id = 'panel-' + scope + '-_meta';
        panel.innerHTML = '<pre>' + escHtml(JSON.stringify(data._meta, null, 2)) + '</pre>';
        panels.appendChild(panel);
      }

      updateResultsInfo(scope);
      $(S.resultsCard).classList.remove('hidden');
      $(S.resultsCard).scrollIntoView({ behavior: 'smooth' });
    }

    function activateTab(scope, key) {
      document.querySelectorAll('#' + SCOPES[scope].tabBar + ' .tab').forEach(t => t.classList.toggle('active', t.dataset.cat === key));
      document.querySelectorAll('#' + SCOPES[scope].tabPanels + ' .tab-panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + scope + '-' + key));
    }

    // ── Copy / Download (scoped) ────────────────────────────────────────────
    function copyResults(scope) {
      const r = SCOPES[scope].state.result;
      if (!r) { showAlert('Nothing to copy'); return; }
      navigator.clipboard.writeText(JSON.stringify(r, null, 2))
        .then(() => showAlert('Copied!', 'success')).catch(e => showAlert(e.message));
    }
    function downloadResults(scope) {
      const r = SCOPES[scope].state.result;
      if (!r) { showAlert('Nothing to download'); return; }
      const name = scope === 'account' ? 'cloudflare-one' : scopeTargetName('zone');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      triggerDownload(JSON.stringify(r, null, 2), 'cf-config-' + name + '-' + ts + '.json', 'application/json');
    }
    function triggerDownload(content, filename, mime) {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([content], { type: mime }));
      a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    }

    // ── Version table cells (shared renderers) ─────────────────────────────
    function objectChangesCell(v) {
      const s = v.change_summary;
      if (!s) return '<span class="muted">—</span>';
      const added = (s.item_added || 0) + (s.added || 0);
      return '<span title="' + escHtml(JSON.stringify(s)) + '">'
        + '<span class="badge badge-added">+' + added + '</span>'
        + '<span class="badge badge-removed">&minus;' + (s.item_removed || 0) + '</span>'
        + '<span class="badge badge-changed">~' + (s.item_changed || 0) + '</span>'
        + '<span class="muted"> ' + (s.endpoints || 0) + ' ep</span>'
        + '</span>';
    }
    function kindCell(v) {
      if (v.named) return '<span class="badge badge-named" title="Named snapshot — pinned, exempt from retention">&#128204; named</span>';
      if (v.kind === 'delta') return '<span class="muted mono">delta ' + (v.chain_depth || 1) + '&Delta;</span>';
      return '<span class="badge badge-changed">full</span>';
    }
    function descriptionCell(v) {
      if (v.named) return '<b>' + escHtml(v.label || '') + '</b>';
      if (v.trigger_type === 'pre_rollback' && !v.label) return '<span class="muted">auto: state before rollback</span>';
      if (v.trigger_type === 'scheduled' && !v.label) return '<span class="muted">scheduled change detection</span>';
      return escHtml(v.label || '—');
    }

    // ── Save / check / list versions (scoped) ───────────────────────────────
    async function saveVersion(scope) {
      const S = SCOPES[scope];
      if (!S.state.result) { showAlert('Fetch configurations first'); return; }
      const label = prompt('Optional description for this version (e.g. "before security review"):');
      if (label === null) return; // cancelled
      try {
        const snap = await api('POST', '/api/snapshots', {
          payload: S.state.result,
          label: label || null,
          zone_name: scopeTargetName(scope),
        });
        S.state.savedState = true;
        S.state.liveMatches = true; // the fetch was just saved (or proven identical) → latest = live
        if (snap.no_change) {
          showAlert('No changes since v' + snap.version + ' — no new version created', 'success');
        } else {
          const s = snap.change_summary;
          showAlert('Recorded as v' + snap.version + (s ? ' — ' + s.endpoints + ' endpoint(s) changed' : ' (full snapshot)'), 'success');
        }
        updateResultsInfo(scope);
        loadVersions(scope);
        loadAudit(true);
        loadOverview();
      } catch (e) { showAlert('Error saving version: ' + e.message); }
    }

    async function saveNamedSnapshot(scope) {
      const S = SCOPES[scope];
      if (!S.state.result) { showAlert('Fetch configurations first — the current fetch is the snapshot source'); return; }
      const def = 'config_' + new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
      const name = prompt('Named snapshot name (up to 64 chars, pinned and exempt from retention):', def);
      if (name === null) return; // cancelled
      try {
        const snap = await api('POST', '/api/snapshots', {
          payload: S.state.result,
          name: name || def,
          zone_name: scopeTargetName(scope),
        });
        showAlert('Named snapshot saved as v' + snap.version + ' — "' + (name || def) + '"', 'success');
        S.state.savedState = true;
        updateResultsInfo(scope);
        loadVersions(scope);
        loadAudit(true);
        loadOverview();
      } catch (e) { showAlert('Error saving named snapshot: ' + e.message); }
    }

    async function checkChanges(scope) {
      const targetId = scopeTargetId(scope);
      if (!targetId) { showAlert(scope === 'account' ? 'Account ID missing' : 'Select a zone'); return; }
      if (!$('api-token').value.trim()) { showAlert('Checking requires your Cloudflare API token'); return; }
      const btn = $(SCOPES[scope].checkBtn);
      btn.disabled = true; btn.textContent = 'Checking…';
      try {
        const r = await api('POST', '/api/versions/check', { zone_id: targetId });
        if (r.no_change) {
          showAlert('No changes detected since v' + r.version, 'success');
        } else {
          const s = r.change_summary;
          showAlert('Change detected — recorded as v' + r.version + (s ? ' (' + s.endpoints + ' endpoint(s) changed)' : ''), 'success');
        }
        SCOPES[scope].state.savedState = true;
        SCOPES[scope].state.liveMatches = true; // drift was just recorded → latest = live
        updateResultsInfo(scope);
        loadVersions(scope);
        loadAudit(true);
        loadOverview();
      } catch (e) { showAlert('Error: ' + e.message); }
      finally { btn.disabled = false; btn.textContent = 'Check for changes'; }
    }

    async function loadVersions(scope) {
      const S = SCOPES[scope];
      const card = $(S.versionsCard);
      card.classList.remove('hidden');
      const targetId = scopeTargetId(scope);
      if (!targetId) {
        $(S.versionsTbody).innerHTML =
          '<tr><td colspan="7" class="muted" style="padding:16px">' +
          (scope === 'account'
            ? 'Connect from the <b>Settings</b> page — your account is detected automatically, and the Cloudflare One version history appears here.'
            : 'Connect from the <b>Settings</b> page, pick a zone, <b>Fetch Configurations</b>, then <b>Save as Version</b>.<br>After the first version, this table shows every recorded change, and <b>Check for changes</b> / <b>Restore</b> become the daily workflow: detect drift → review the diff → roll back to any previous version.') +
          '</td></tr>';
        $(S.versionsInfo).textContent = '';
        return;
      }
      try {
        const r = await api('GET', '/api/snapshots?zone_id=' + targetId);
        S.state.versions = r.snapshots || [];
        renderVersions(scope);
      } catch (e) {
        $(S.versionsTbody).innerHTML = '<tr><td colspan="7" class="muted" style="padding:14px">Could not load versions: ' + escHtml(e.message) + '</td></tr>';
      }
    }

    function filteredVersions(scope) {
      const S = SCOPES[scope];
      const trig = $(S.filterTrigger) ? $(S.filterTrigger).value : '';
      const kind = $(S.filterKind) ? $(S.filterKind).value : '';
      const q = $(S.filterSearch) ? $(S.filterSearch).value.trim().toLowerCase() : '';
      return S.state.versions.filter(v => {
        if (trig && v.trigger_type !== trig) return false;
        if (kind === 'named' && !v.named) return false;
        if (kind === 'full' && !(v.kind === 'full' && !v.named)) return false;
        if (kind === 'delta' && v.kind !== 'delta') return false;
        if (q && !((v.label || '') + ' ' + (v.created_by || '') + ' ' + (v.trigger_type || '') + ' v' + v.version).toLowerCase().includes(q)) return false;
        return true;
      });
    }

    function resetVerFilters(scope) {
      const S = SCOPES[scope];
      $(S.filterTrigger).value = '';
      $(S.filterKind).value = '';
      $(S.filterSearch).value = '';
      renderVersions(scope);
    }

    // Context-aware fetch button per page: primary before the first baseline
    // exists, secondary once "Check for changes" is the daily primary action.
    function updatePrimaryButton(scope) {
      const S = SCOPES[scope];
      const btn = $(S.fetchBtn);
      if (!btn) return;
      const hasBaseline = S.state.versions.length > 0;
      btn.classList.toggle('btn-primary', !hasBaseline);
      btn.classList.toggle('btn-outline', hasBaseline);
      const label = hasBaseline
        ? (scope === 'account' ? 'Fetch Cloudflare One Configuration' : 'Fetch Configurations')
        : (scope === 'account' ? 'Fetch & Save First Version' : 'Fetch & Save First Version');
      if (btn.textContent.indexOf('…') === -1) btn.textContent = label;
      btn.title = hasBaseline ? '' : 'Fetch the configuration, then save it as the first version baseline';
    }

    function renderVersions(scope) {
      const S = SCOPES[scope];
      const card = $(S.versionsCard);
      const tbody = $(S.versionsTbody);
      card.classList.remove('hidden');
      updatePrimaryButton(scope);
      if (!S.state.versions.length) {
        tbody.innerHTML =
          '<tr><td colspan="7" class="muted" style="padding:16px">No versions for this target yet.<br>' +
          'Fetch the configuration above, then click <b>Save as Version</b> (or <b>Save Named Snapshot</b> for a pinned known-good state).<br>' +
          'Once the first version exists, changes are recorded automatically every 5 minutes — and each row here can be compared, loaded or restored.</td></tr>';
        $(S.versionsInfo).textContent = '0 versions';
        return;
      }
      const shown = filteredVersions(scope);
      const latestV = S.state.versions.find(v => !v.deleted_at);
      tbody.innerHTML = '';
      shown.forEach(v => {
        const isLatest = latestV && v.id === latestV.id;
        const currentBadge = !isLatest ? '' : (
          S.state.liveMatches === true
            ? ' <span class="badge badge-added" title="Latest version — matches the live configuration">current</span>'
            : S.state.liveMatches === false
              ? ' <span class="badge badge-warn" title="Latest recorded version — the live configuration has unsaved changes (see the banner above / Refresh to re-check)">latest — live drifted</span>'
              : ' <span class="badge badge-changed" title="Latest recorded version">latest</span>');
        const tr = document.createElement('tr');
        if (v.deleted_at) tr.style.opacity = '.5';
        tr.innerHTML =
          '<td><b>v' + v.version + '</b>' + currentBadge +
            (v.scope === 'account' ? ' <span class="badge badge-acct" title="Account-level configuration (Cloudflare One)">account</span>' : '') +
            (v.trigger_type === 'pre_rollback' ? ' <span class="badge badge-auto" title="Automatic safety snapshot taken before a rollback">auto</span>' : '') + '</td>' +
          '<td>' + objectChangesCell(v) + '</td>' +
          '<td>' + new Date(v.created_at).toLocaleString() + '</td>' +
          '<td>' + escHtml(v.created_by) + '</td>' +
          '<td>' + descriptionCell(v) + '</td>' +
          '<td>' + kindCell(v) + '</td>' +
          '<td class="row-actions">' +
            '<button class="link-btn" onclick="loadVersion(\\'' + v.id + '\\')" title="Load this version as the candidate in Results">View</button>' +
            '<button class="link-btn" onclick="viewVersionChanges(\\'' + v.id + '\\')" title="What changed in this version vs the previous one">Changes</button>' +
            '<button class="link-btn" onclick="diffVersionLive(\\'' + v.id + '\\')" title="Compare this version with the current live configuration">Diff</button>' +
            '<button class="link-btn" onclick="rollbackVersion(\\'' + v.id + '\\')" title="Roll the live configuration back to this version" style="font-weight:700">Restore</button>' +
            (v.deleted_at ? '' : '<button class="link-btn link-danger" onclick="deleteVersion(\\'' + v.id + '\\')">Delete</button>') +
          '</td>';
        tbody.appendChild(tr);
      });
      if (!shown.length) tbody.innerHTML = '<tr><td colspan="7" class="muted" style="padding:14px">No versions match the current filters.</td></tr>';
      let info = shown.length + ' of ' + S.state.versions.length + ' version(s)';
      if (latestV && S.state.liveMatches === true) info += ' \u00b7 v' + latestV.version + ' is current (matches live)';
      $(S.versionsInfo).textContent = info;

      // populate compare selects
      const a = $(S.cmpA), b = $(S.cmpB);
      a.innerHTML = ''; b.innerHTML = '';
      S.state.versions.forEach((v, i) => {
        const o1 = document.createElement('option');
        o1.value = v.id;
        o1.textContent = 'v' + v.version + (v.label ? ' — ' + v.label : '');
        a.appendChild(o1);
        const o2 = o1.cloneNode(true);
        if (i === Math.min(1, S.state.versions.length - 1)) o2.selected = true;
        b.appendChild(o2);
      });
    }

    // ── Version actions (id-based, work on either page) ─────────────────────
    async function loadVersion(id) {
      try {
        const payload = await api('GET', '/api/snapshots/' + id);
        const scope = scopeForVersion(id);
        const S = SCOPES[scope];
        S.state.result = payload;
        const cats = (payload._meta && payload._meta.categories_requested) ||
          Object.keys(payload).filter(k => k !== '_meta');
        renderResults(payload, cats, scope);
        showAlert('Loaded v' + (payload._meta && payload._meta.version ? payload._meta.version : '') +
          ' as candidate — shown in Results. Save as Version / Named Snapshot to record it as a new version.', 'success');
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    async function viewVersionChanges(id) {
      try {
        const r = await api('GET', '/api/versions/' + id + '/changes');
        if (r.kind !== 'delta' || !r.changes || !r.changes.length) {
          showAlert('v' + r.version + ' is a full snapshot — complete state recorded, no delta to display', 'warning');
          return;
        }
        renderStructuredDiff(
          { changes: r.changes, summary: r.summary, skipped: [], truncated: false },
          'v' + r.version + ' recorded changes (vs v' + r.from_version + ')'
        );
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    async function diffVersionLive(id) {
      try {
        const r = await api('GET', '/api/snapshots/' + id + '/diff?vs=live');
        renderStructuredDiff(r, 'v' + r.snapshot.version + ' → live');
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    async function compareVersions(scope) {
      const S = SCOPES[scope];
      const a = $(S.cmpA).value, b = $(S.cmpB).value;
      if (!a || !b) { showAlert('Select two versions to compare', 'warning'); return; }
      if (a === b) { showAlert('Select two different versions', 'warning'); return; }
      try {
        const r = await api('GET', '/api/snapshots/' + a + '/diff?vs=' + b);
        renderStructuredDiff(r, 'v' + r.snapshot.version + ' → ' + r.vs);
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    async function deleteVersion(id) {
      const scope = scopeForVersion(id);
      const v = SCOPES[scope].state.versions.find(x => x.id === id);
      const name = v ? ('v' + v.version + (v.label ? ' (“' + v.label + '”)' : '')) : 'this version';
      if (!confirm('Soft-delete ' + name + '? Metadata is retained and the deletion is recorded in the audit trail. Pre-rollback safety snapshots must be force-deleted.')) return;
      try {
        await api('DELETE', '/api/snapshots/' + id);
        showAlert('Version deleted (soft)', 'success');
        loadVersions(scope);
        loadAudit(true);
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    // ── Structured diff rendering (shared) ──────────────────────────────────
    function groupChangesByCategory(changes) {
      const groups = new Map();
      for (const c of changes) {
        const cat = String(c.path || '').split('.')[0] || 'other';
        if (!groups.has(cat)) groups.set(cat, []);
        groups.get(cat).push(c);
      }
      return groups;
    }

    function changesRowsHtml(changes) {
      let html = '';
      changes.forEach(c => {
        const kind = c.type === 'added' ? 'added' : c.type === 'removed' ? 'removed' : 'changed';
        html += '<div class="diff-row">' +
          '<span class="badge badge-' + kind + '">' + kind + '</span>' +
          '<span class="diff-path">' + escHtml(c.path) + '</span>';
        if (c.type === 'added') {
          html += diffCodeBlock('+', 'plus', c.after);
        } else if (c.type === 'removed') {
          html += diffCodeBlock('−', 'minus', c.before);
        } else {
          html += diffCodeBlock('−', 'minus', c.before) + diffCodeBlock('+', 'plus', c.after);
        }
        html += '</div>';
      });
      return html;
    }

    // Renders a +/- value as a code block (pretty JSON for objects).
    function diffCodeBlock(sign, cls, v) {
      let text;
      if (typeof v === 'string') text = v;
      else {
        try { text = JSON.stringify(v, null, 2); } catch (e) { text = String(v); }
      }
      if (text === undefined) text = 'undefined';
      if (text === null) text = 'null';
      if (text.length > 800) text = text.slice(0, 800) + '\\n…(' + (text.length - 800) + ' more chars)';
      return '<pre class="diff-code ' + cls + '">' + escHtml(sign + ' ' + text) + '</pre>';
    }

    function diffHtml(r) {
      if (!r.changes || !r.changes.length) {
        return '<div class="diff-empty">No differences found.' +
          ((r.skipped && r.skipped.length) ? ' (' + r.skipped.length + ' endpoint(s) unavailable for comparison)' : '') + '</div>';
      }
      let html = '';
      if (r.skipped && r.skipped.length) {
        html += '<div class="alert alert-warning">Endpoints unavailable for comparison: ' +
          r.skipped.map(s => escHtml(s.category + '.' + s.endpoint)).join(', ') + '</div>';
      }
      const s = r.summary || { added: 0, removed: 0, changed: 0 };
      html += '<div class="diff-summary">' +
        '<span class="badge badge-added">' + s.added + ' added</span>' +
        '<span class="badge badge-removed">' + s.removed + ' removed</span>' +
        '<span class="badge badge-changed">' + s.changed + ' changed</span>' +
        (r.truncated ? '<span class="badge badge-warn">list truncated at 500 changes</span>' : '') +
        '</div>';

      const groups = groupChangesByCategory(r.changes);
      if (groups.size <= 1) {
        html += '<div class="diff-list">' + changesRowsHtml(r.changes) + '</div>';
        return html;
      }
      for (const [cat, catChanges] of groups) {
        const gc = { added: 0, removed: 0, changed: 0 };
        catChanges.forEach(c => { if (gc[c.type] !== undefined) gc[c.type]++; });
        html += '<details class="diff-group" open><summary>' +
          '<b>' + escHtml(catLabel(cat)) + '</b> ' +
          '<span class="badge badge-added">+' + gc.added + '</span>' +
          '<span class="badge badge-removed">&minus;' + gc.removed + '</span>' +
          '<span class="badge badge-changed">~' + gc.changed + '</span>' +
          '</summary><div class="diff-list">' + changesRowsHtml(catChanges) + '</div></details>';
      }
      return html;
    }

    function renderStructuredDiff(r, title) {
      const card = $('diff-card');
      $('diff-title').textContent = 'Configuration Diff — ' + title;
      $('diff-output').innerHTML = diffHtml(r);
      card.classList.remove('hidden');
      card.scrollIntoView({ behavior: 'smooth' });
    }

    // ── Restore (stepped: scope → review → result; shared modal) ────────────
    function rollbackVersion(id) {
      const scope = scopeForVersion(id);
      const v = SCOPES[scope].state.versions.find(x => x.id === id);
      if (!v) return;
      if (!$('api-token').value.trim()) {
        showAlert('Restore needs your Cloudflare API token (with Edit permissions) in the Credentials field');
        return;
      }
      const boxes = v.categories.map(c =>
        '<label class="modal-cat"><input type="checkbox" checked value="' + escHtml(c) + '">' +
        escHtml(catLabel(c)) + ' <span class="muted">(' + escHtml(c) + ')</span></label>').join('');
      $('modal-body').innerHTML =
        '<div class="modal-head"><h3>' + (v.scope === 'account'
          ? 'Restore account configuration (Cloudflare One) to v' + v.version
          : 'Restore ' + escHtml(v.zone_name) + ' to v' + v.version) + '</h3>' +
        '<div class="muted">Saved ' + new Date(v.created_at).toLocaleString() + ' by ' + escHtml(v.created_by) +
        (v.label ? ' — “' + escHtml(v.label) + '”' : '') + '</div></div>' +
        '<div class="rb-steps">' +
          '<span class="rb-step active" id="rb-step-1">1 · Select scope</span>' +
          '<span class="rb-step" id="rb-step-2">2 · Review changes</span>' +
          '<span class="rb-step" id="rb-step-3">3 · Result</span>' +
        '</div>' +
        '<p class="modal-note">Choose the scope, then <b>Preview changes</b>: the exact configuration diff (live → v' + v.version + ') and every planned write operation, <b>before anything is touched</b>. The live state is saved automatically before execution, so the restore itself can be undone. A restore bumps the version number.</p>' +
        '<div class="modal-cats">' + boxes + '</div>' +
        '<div class="modal-actions">' +
          '<button class="btn btn-outline" id="rb-preview-btn" onclick="doRollback(\\'' + v.id + '\\', true)">Preview changes (dry run)</button>' +
          '<button class="btn btn-primary" id="rb-execute-btn" disabled title="Run Preview changes first — review the diff before committing" onclick="doRollback(\\'' + v.id + '\\', false)">Execute restore</button>' +
          '<button class="btn" onclick="closeModal()">Cancel</button>' +
        '</div>' +
        '<div id="rollback-result"></div>';
      $('modal-overlay').classList.remove('hidden');
    }

    function closeModal() { $('modal-overlay').classList.add('hidden'); }

    function setRbStep(n) {
      for (let i = 1; i <= 3; i++) {
        const el = $('rb-step-' + i);
        if (el) el.classList.toggle('active', i <= n);
      }
    }

    // Animated stage feedback while the restore request is in flight.
    function startRbProgress(el, dryRun) {
      const stages = dryRun
        ? ['Fetching live configuration…', 'Comparing live state against v-target…', 'Planning write operations…']
        : ['Fetching live configuration…', 'Saving safety snapshot of live state…', 'Applying write operations…', 'Verifying restored state…', 'Recording the restore in version history…'];
      let i = 0;
      el.innerHTML = '<div class="alert alert-warning" id="rb-progress"><span class="rb-spinner"></span> ' + stages[0] + '</div>';
      const timer = setInterval(() => {
        i = Math.min(i + 1, stages.length - 1);
        const p = $('rb-progress');
        if (p) p.innerHTML = '<span class="rb-spinner"></span> ' + stages[i];
      }, 5000);
      return function stop() {
        clearInterval(timer);
        const p = $('rb-progress');
        if (p) p.remove();
      };
    }

    async function doRollback(id, dryRun) {
      const scope = scopeForVersion(id);
      const result = $('rollback-result');
      const cats = Array.from(document.querySelectorAll('.modal-cat input:checked')).map(i => i.value);
      if (!cats.length) { result.innerHTML = '<div class="alert alert-warning">Select at least one category</div>'; return; }
      if (!dryRun && !confirm('Execute restore now? Live Cloudflare configuration will be modified.')) return;
      const prevBtn = $('rb-preview-btn');
      const execBtn = $('rb-execute-btn');
      if (prevBtn) prevBtn.disabled = true;
      if (execBtn) execBtn.disabled = true;
      setRbStep(dryRun ? 2 : 3);
      const stopProgress = startRbProgress(result, dryRun);
      try {
        const r = await api('POST', '/api/rollback', { snapshot_id: id, categories: cats, dry_run: dryRun });
        stopProgress();
        renderRollbackReport(r, dryRun);
        if (!dryRun) {
          // restored state was verified → the new rollback version matches live
          SCOPES[scope].state.liveMatches = (r.report && r.report.totals && r.report.totals.not_verified === 0) ? true : null;
          loadVersions(scope);
          loadVersions(scope === 'zone' ? 'account' : 'zone');
          loadAudit(true);
          loadOverview();
        } else {
          // Diff reviewed — unlock execution (review-before-commit is enforced)
          if (execBtn) { execBtn.disabled = false; execBtn.title = 'Apply the reviewed changes to live'; }
          setRbStep(3);
        }
      } catch (e) {
        stopProgress();
        result.innerHTML = '<div class="alert alert-danger">Error: ' + escHtml(e.message) + '</div>';
        if (execBtn) execBtn.disabled = true;
      } finally {
        if (prevBtn) prevBtn.disabled = false;
      }
    }

    function renderRollbackReport(r, dryRun) {
      const rep = r.report;
      const t = rep.totals;
      let html = '';

      // Pre-commit diff: exactly what the rollback will change (live → vN)
      if (r.state_diff && r.state_diff.changes && r.state_diff.changes.length) {
        const s = r.state_diff.summary || {};
        html += '<div class="rb-section-title">Changes that will be applied <span class="muted">(live → v' + r.snapshot.version + ')</span></div>';
        html += '<div class="alert alert-warning">Rolling back will restore <b>+' + (s.added || 0) + '</b>, ' +
          'remove <b>&minus;' + (s.removed || 0) + '</b> and change <b>~' + (s.changed || 0) + '</b> item(s). ' +
          'Review the full diff before committing.</div>';
        html += '<details class="rb-entry" open><summary><span class="chip chip-warn">diff</span> <b>Configuration changes (live → v' + r.snapshot.version + ')</b></summary>' +
          '<div class="rb-diff">' + diffHtml({ changes: r.state_diff.changes, summary: r.state_diff.summary, skipped: [], truncated: r.state_diff.truncated }) + '</div></details>';
      } else {
        html += '<div class="alert alert-success">No configuration differences found between live and v' + r.snapshot.version + ' — nothing to roll back.</div>';
      }

      if (r.pre_snapshot) {
        html += '<div class="alert alert-success">Safety snapshot: <b>v' + r.pre_snapshot.version + '</b>' +
          (r.pre_snapshot.no_change ? ' (live state already recorded — roll back to it to undo this rollback)' : ' — the state before this rollback. Roll back to it to undo this rollback.') + '</div>';
      }
      if (r.post_restore_version) {
        html += '<div class="alert alert-success">Restored state recorded as <b>v' + r.post_restore_version.version +
          '</b> — a restore bumps the version number, so this restore is itself part of the history.</div>';
      } else if (r.post_restore_error) {
        html += '<div class="alert alert-warning">Restored state could not be recorded as a new version: ' + escHtml(r.post_restore_error) + '</div>';
      }
      if (dryRun) {
        if (!t.planned) {
          html += '<div class="alert alert-success">No write operations needed — the selected categories already match v' + r.snapshot.version + '.</div>';
        } else {
          html += '<div class="alert alert-warning">Planned: <b>' + t.ops_total + '</b> write operation(s) across ' + t.planned + ' endpoint(s). Review the diff above and the operations below, then press Execute rollback.</div>';
        }
      } else {
        const cls = (t.ops_failed || t.error) ? 'alert-warning' : 'alert-success';
        html += '<div class="alert ' + cls + '"><b>Restore summary:</b> ' + t.ops_ok + ' of ' + t.ops_total +
          ' write operation(s) applied · ' + t.verified + '/' + (t.verified + t.not_verified) + ' endpoints verified against v' +
          r.snapshot.version + (r.post_restore_version ? ' · restored state recorded as v' + r.post_restore_version.version : '') + '</div>';
      }
      html += '<div class="rb-entries">';
      rep.entries.forEach(e => {
        const statusCls = { restored: 'ok', planned: 'warn', unchanged: 'ok', view_only: 'skip', skipped: 'skip', error: 'err', no_data: 'skip', partial: 'warn' }[e.status] || 'skip';
        html += '<details class="rb-entry" ' + ((e.ops && e.ops.length) ? 'open' : '') + '>' +
          '<summary><span class="chip chip-' + statusCls + '">' + e.status + '</span> <b>' + escHtml(e.category + ' · ' + e.endpoint) + '</b>' +
          ' <span class="muted">' + (e.ops ? e.ops.length + ' op(s)' : '') + (e.unchanged ? ' · ' + e.unchanged + ' unchanged' : '') + '</span></summary>';
        if (e.note) html += '<div class="muted rb-note">' + escHtml(e.note) + '</div>';
        (e.warnings || []).forEach(w => { html += '<div class="alert alert-warning">' + escHtml(w) + '</div>'; });
        if (e.verification) {
          html += '<div class="muted rb-note">Verification: ' + (e.verification.verified
            ? '✓ live state matches the snapshot'
            : '✗ ' + escHtml(e.verification.note || 'differs from snapshot')) + '</div>';
        }
        const ops = dryRun ? e.ops : (e.op_results || []);
        ops.forEach(op => {
          const kindIcon = { create: '+', update: '~', delete: '×', set: '=' }[op.kind] || '·';
          let cls = '';
          if (op.ok !== undefined) cls = op.ok ? 'diff-added' : 'diff-removed';
          else if (op.kind === 'delete') cls = 'diff-removed';
          else if (op.kind === 'create') cls = 'diff-added';
          html += '<div class="rb-op ' + cls + '">' + kindIcon + ' [' + op.method + '] ' + escHtml(op.describe) +
            (op.error ? ' — <b>failed:</b> ' + escHtml(op.error) : '') + '</div>';
        });
        html += '</details>';
      });
      html += '</div>';
      $('rollback-result').innerHTML = html;
    }

    // ── Zone comparison (AppSec page) ───────────────────────────────────────
    function showCompare() {
      $('compare-card').classList.remove('hidden');
      $('compare-card').scrollIntoView({ behavior: 'smooth' });
    }
    async function compareZones() {
      const token = $('api-token').value.trim();
      const z1 = $('zone-select').value;
      const z2 = $('compare-zone-select').value;
      const cat = $('compare-cat-select').value;
      const accountId = $('account-id').value.trim();
      if (z1 === z2) { showAlert('Select two different zones', 'warning'); return; }
      const qs = new URLSearchParams({ cats: cat });
      if (accountId) qs.set('accountId', accountId);
      try {
        const [r1, r2] = await Promise.all([
          fetch('/api/configs/' + z1 + '?' + qs, { headers: { 'Authorization': token } }).then(r => r.json()),
          fetch('/api/configs/' + z2 + '?' + qs, { headers: { 'Authorization': token } }).then(r => r.json()),
        ]);
        const n1 = $('zone-select').options[$('zone-select').selectedIndex].text;
        const n2 = $('compare-zone-select').options[$('compare-zone-select').selectedIndex].text;
        const d = await api('POST', '/api/diff', { a: r1[cat] || {}, b: r2[cat] || {} });
        renderStructuredDiff(d, n1 + ' → ' + n2);
      } catch (e) { showAlert('Error: ' + e.message); }
    }

    // ── Audit Log page ──────────────────────────────────────────────────────
    async function loadAudit(reset) {
      if (reset) auditOffset = 0;
      const p = new URLSearchParams();
      const zoneId = $('audit-zone-select').value;
      if (zoneId) p.set('zone_id', zoneId);
      const actor = $('audit-actor').value.trim();
      if (actor) p.set('actor', actor);
      const action = $('audit-action').value;
      if (action) p.set('action', action);
      const from = $('audit-from').value;
      if (from) p.set('from', from + 'T00:00:00.000Z');
      const to = $('audit-to').value;
      if (to) p.set('to', to + 'T23:59:59.999Z');
      p.set('limit', String(AUDIT_PAGE));
      p.set('offset', String(auditOffset));
      try {
        const r = await api('GET', '/api/audit?' + p.toString());
        renderAudit(r);
      } catch (e) {
        $('audit-tbody').innerHTML = '<tr><td colspan="6" class="muted">Could not load audit log: ' + escHtml(e.message) + '</td></tr>';
      }
    }

    function resetAuditFilters() {
      $('audit-zone-select').value = '';
      $('audit-action').value = '';
      $('audit-actor').value = '';
      $('audit-from').value = '';
      $('audit-to').value = '';
      loadAudit(true);
    }

    function renderAudit(r) {
      const tbody = $('audit-tbody');
      tbody.innerHTML = '';
      r.entries.forEach(e => {
        const tr = document.createElement('tr');
        const outCls = e.outcome === 'success' ? 'ok' : (e.outcome === 'partial' ? 'warn' : (e.outcome === 'denied' ? 'warn' : 'err'));
        tr.innerHTML =
          '<td>' + new Date(e.ts).toLocaleString() + '</td>' +
          '<td>' + escHtml(e.actor) + '</td>' +
          '<td><span title="' + escHtml(e.action) + '">' + escHtml(auditLabel(e.action)) + '</span>' +
            ' <span class="muted mono">' + escHtml(e.action) + '</span></td>' +
          '<td>' + escHtml(e.zone_name || e.zone_id || '—') + '</td>' +
          '<td><span class="chip chip-' + outCls + '">' + escHtml(e.outcome) + '</span></td>' +
          '<td>' + (e.details
            ? '<details><summary class="link-btn">view</summary><pre class="audit-pre">' +
              escHtml(typeof e.details === 'string' ? e.details : JSON.stringify(e.details, null, 2)) + '</pre></details>'
            : '—') + '</td>';
        tbody.appendChild(tr);
      });
      if (!r.entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No audit entries match the current filters.</td></tr>';
      }
      const shown = r.entries.length ? ((r.offset + 1) + '–' + Math.min(r.offset + r.entries.length, r.total)) : '0';
      $('audit-nav').textContent = 'Showing ' + shown + ' of ' + r.total + ' entries';
      $('audit-prev').disabled = r.offset <= 0;
      $('audit-next').disabled = r.offset + r.entries.length >= r.total;
    }

    function auditPrev() { auditOffset = Math.max(0, auditOffset - AUDIT_PAGE); loadAudit(false); }
    function auditNext() { auditOffset += AUDIT_PAGE; loadAudit(false); }

    init();
  </script>
</body>
</html>`;
