// ─── Config category definitions ────────────────────────────────────────────
// Policy-centric scope: Cloudflare One (Zero Trust) at the account level, and
// AppSec (WAF, DDoS, Bot, API Shield), TLS, CDN/caching and DNS at the zone
// level. Developer products (Workers, Pages, KV, D1, R2, Queues, AI Gateway,
// Vectorize, Email Routing, Logpush, Notifications, LB, Spectrum, Magic WAN,
// account members/roles) are intentionally OUT of scope.
//
// Each entry: { label, key, endpoints[] }
// endpoints: { name, path(zoneId,accountId), accountRequired?, scope?, product?, desc? }
//   scope:   'zone' (default) | 'account' — storage/versioning level
//   product: 'appsec' (default) | 'one' — which product page owns it.
//            AppSec = WAF family: zone-level WAF/DDoS/Bot/API Shield + TLS/CDN/DNS
//            context PLUS account-level WAF (custom rules, IP access rules).
//            One = pure Zero Trust (Access, Gateway, tunnels, devices, DLP).
//   desc:    plain-English description of what the setting controls (shown on
//            the Reference page). Omitted runtime data is never versioned.
// If a request returns 401/403/404/4xx → silently omit that key.
// List endpoints that are rollback-eligible carry ?per_page= so snapshots are
// not silently truncated (the rollback engine refuses to reconcile lists that
// may be paginated).

export const CATEGORIES = [
  {
    label: 'Application Security (WAF, DDoS, Bot, API Shield)',
    key: 'appsec',
    endpoints: [
      { name: 'rulesets',              desc: 'Inventory of all Ruleset Engine configurations on the zone (every phase entrypoint and custom ruleset). Reference view — each phase is versioned and restored individually.', path: (z)=>`zones/${z}/rulesets` },
      { name: 'waf_managed_rules',    desc: 'Classic WAF managed rule packages (Cloudflare Managed, OWASP Core): sensitivity, action and detection mode. Restored per package.', path: (z)=>`zones/${z}/firewall/waf/packages` },
      { name: 'waf_overrides',        desc: 'Classic WAF per-rule overrides on top of the managed packages (enable/disable individual rules, change their action).', path: (z)=>`zones/${z}/firewall/waf/overrides?per_page=100` },
      { name: 'firewall_rules',       desc: 'Firewall Rules: custom expressions with actions (block, managed challenge, skip, log…) evaluated against incoming traffic.', path: (z)=>`zones/${z}/firewall/rules?per_page=100` },
      { name: 'ip_access_rules_zone', desc: 'Zone-level IP Access Rules: allow / challenge / block by IP, IP range, ASN, country code or continent.', path: (z)=>`zones/${z}/firewall/access_rules/rules?per_page=100` },
      { name: 'user_agent_rules',     desc: 'User-Agent Blocking Rules: block or challenge requests from specific browser user-agent strings.', path: (z)=>`zones/${z}/firewall/ua_rules?per_page=100` },
      { name: 'lockdowns',            desc: 'Zone Lockdown: restrict specific URL patterns to whitelisted IP addresses/countries; everyone else gets 403.', path: (z)=>`zones/${z}/firewall/lockdowns?per_page=100` },
      { name: 'rate_limits',          desc: 'Classic Rate Limiting rules: thresholds, periods and mitigation actions for request floods.', path: (z)=>`zones/${z}/rate_limits?per_page=100` },
      { name: 'managed_headers',      desc: 'Managed HTTP response headers: enable/disable security headers (HSTS, X-XSS-Protection, X-Content-Type-Options, X-Frame-Options…).', path: (z)=>`zones/${z}/managed_headers` },
      { name: 'transform_rules',      desc: 'Transform Rules: rewrite request headers, response headers and URL paths based on expressions.', path: (z)=>`zones/${z}/rulesets/phases/http_request_transform/entrypoint` },
      { name: 'redirect_rules',       desc: 'Dynamic URL Redirect Rules: expression-matched 3xx redirects with preserved query strings and source URLs.', path: (z)=>`zones/${z}/rulesets/phases/http_request_dynamic_redirect/entrypoint` },
      { name: 'config_rules',         desc: 'Configuration Rules: override zone-level settings (security level, cache TTL, Rocket Loader…) for matching traffic.', path: (z)=>`zones/${z}/rulesets/phases/http_config_settings/entrypoint` },
      { name: 'ddos_http_overrides', desc: 'HTTP DDoS Protection: per-zone sensitivity overrides and rule toggles for the L7 DDoS managed ruleset.', path: (z)=>`zones/${z}/rulesets/phases/ddos_l7/entrypoint` },
      { name: 'bot_management',      desc: 'Bot Management: JS detection, machine-learning bot scoring, AI-bot protection and verified-bot handling.', path: (z)=>`zones/${z}/bot_management` },
      { name: 'security_level',      desc: 'Security Level: how aggressively Cloudflare challenges visitors (Off → Essentially Off → Low → Medium → High → Under Attack).', path: (z)=>`zones/${z}/settings/security_level` },
      { name: 'challenge_ttl',       desc: 'Challenge TTL: how long a passed challenge (managed challenge / JS challenge) is remembered for the visitor.', path: (z)=>`zones/${z}/settings/challenge_ttl` },
      { name: 'browser_check',       desc: 'Browser Integrity Check: rejects requests from browsers with malformed or suspicious headers.', path: (z)=>`zones/${z}/settings/browser_check` },
      { name: 'hotlink_protection',  desc: 'Hotlink Protection: prevents other sites from hotlinking images and content served from your zone.', path: (z)=>`zones/${z}/settings/hotlink_protection` },
      { name: 'email_obfuscation',   desc: 'Email Obfuscation: rewrites email addresses in served HTML so scrapers cannot harvest them.', path: (z)=>`zones/${z}/settings/email_obfuscation` },
      { name: 'server_side_exclude', desc: 'Server-Side Excludes: hides content between <!--sse--> markers from suspicious visitors.', path: (z)=>`zones/${z}/settings/server_side_exclude` },
      { name: 'security_header',     desc: 'HSTS: HTTP Strict Transport Security header — max-age, subdomains, preload, nosniff.', path: (z)=>`zones/${z}/settings/security_header` },
      { name: 'scrape_shield',       desc: 'Scrape Shield settings for the zone.', path: (z)=>`zones/${z}/settings/scrape_shield` },
      { name: 'ssl',                  desc: 'SSL/TLS encryption mode: Flexible, Full or Strict (Full + origin certificate validation). Controls how Cloudflare connects to your origin.', path: (z)=>`zones/${z}/settings/ssl` },
      { name: 'custom_certificates',  desc: 'Uploaded custom origin certificates. View-only — private keys are never returned by the API, so restores would be incomplete.', path: (z)=>`zones/${z}/custom_certificates` },
      { name: 'custom_hostnames',     desc: 'Cloudflare for SaaS custom hostnames (SSL per customer hostname). View-only — hostname validation state is runtime data.', path: (z)=>`zones/${z}/custom_hostnames` },
      { name: 'api_shield',            desc: 'API Shield configuration: schema validation, mTLS, sequence analysis for API traffic.', path: (z)=>`zones/${z}/api_gateway/configuration` },
      { name: 'api_shield_schemas',    desc: 'API Shield operation schemas: the learned/blocked endpoint definitions used for request validation.', path: (z)=>`zones/${z}/api_gateway/schemas` },
    ]
  },
  {
    label: 'TLS & Network Security',
    key: 'tls',
    endpoints: [
      { name: 'always_use_https',          desc: 'Always Use HTTPS: 301-redirects all plain-HTTP requests to HTTPS.', path: (z)=>`zones/${z}/settings/always_use_https` },
      { name: 'automatic_https_rewrites', desc: 'Automatic HTTPS Rewrites: rewrites insecure http:// links in served HTML to https://.', path: (z)=>`zones/${z}/settings/automatic_https_rewrites` },
      { name: 'tls_min_version',           desc: 'Minimum TLS Version: rejects handshakes below the chosen TLS protocol version (1.0–1.2).', path: (z)=>`zones/${z}/settings/min_tls_version` },
      { name: 'tls_1_3',                  desc: 'TLS 1.3: enables the newest TLS protocol for faster, more secure handshakes.', path: (z)=>`zones/${z}/settings/tls_1_3` },
      { name: 'http2',                     desc: 'HTTP/2: multiplexed connections and header compression for modern browsers.', path: (z)=>`zones/${z}/settings/http2` },
      { name: 'http3',                     desc: 'HTTP/3 (QUIC): UDP-based transport resilient to packet loss.', path: (z)=>`zones/${z}/settings/http3` },
      { name: 'zero_rtt',                  desc: '0-RTT Connection Resumption: lets returning clients send data immediately (faster, replay-risk trade-off).', path: (z)=>`zones/${z}/settings/zero_rtt` },
      { name: 'opportunistic_encryption', desc: 'Opportunistic Encryption: serves HTTP/2 over cleartext port 80 without a redirect.', path: (z)=>`zones/${z}/settings/opportunistic_encryption` },
      { name: 'onion_routing',             desc: 'Opportunistic Onion: serves your site over the Tor network via an onion address.', path: (z)=>`zones/${z}/settings/opportunistic_onion` },
      { name: 'ipv6',                      desc: 'IPv6 Compatibility: serves your zone over IPv6.', path: (z)=>`zones/${z}/settings/ipv6` },
      { name: 'websockets',                desc: 'WebSockets: allows persistent bidirectional connections through Cloudflare.', path: (z)=>`zones/${z}/settings/websockets` },
      { name: 'pseudo_ipv4',              desc: 'Pseudo IPv4: overrides or appends the visitor IP with a synthesized IPv4 for origin compatibility.', path: (z)=>`zones/${z}/settings/pseudo_ipv4` },
      { name: 'ip_geolocation',           desc: 'IP Geolocation Headers: passes visitor country/continent headers to the origin.', path: (z)=>`zones/${z}/settings/ip_geolocation` },
      { name: 'network_error_logging',     desc: 'Network Error Logging: browsers report failed fetches to a defined endpoint via the NEL header.', path: (z)=>`zones/${z}/settings/nel` },
    ]
  },
  {
    label: 'CDN, Caching & Performance',
    key: 'cdn',
    endpoints: [
      { name: 'cache_rules',          desc: 'Cache Rules: modern expression-matched caching controls (eligibility, edge/browser TTL, cache keys, origin fetch).', path: (z)=>`zones/${z}/rulesets/phases/http_request_cache_settings/entrypoint` },
      { name: 'cache_settings',        desc: 'Default zone cache settings: edge TTL, browser TTL, content-type caching overrides.', path: (z)=>`zones/${z}/cache/settings` },
      { name: 'tiered_cache',          desc: 'Smart Tiered Cache Topology: collapses cache fills through upper-tier Cloudflare PoPs to reduce origin load.', path: (z)=>`zones/${z}/cache/tiered_cache_smart_topology_enable` },
      { name: 'cache_reserve',         desc: 'Cache Reserve: persists cached objects in R2 storage to extend edge TTL beyond memory/disk limits.', path: (z)=>`zones/${z}/cache/cache_reserve` },
      { name: 'page_rules',            desc: 'Classic Page Rules: URL-pattern settings (cache level, redirects, origin controls). Superseded by modern rules but still supported.', path: (z)=>`zones/${z}/pagerules?per_page=100` },
      { name: 'minify',                desc: 'Auto Minify: strips whitespace/comments from HTML, CSS and JavaScript responses.', path: (z)=>`zones/${z}/settings/minify` },
      { name: 'polish',                desc: 'Polish: lossless/lossy image optimization, plus WebP conversion at the edge.', path: (z)=>`zones/${z}/settings/polish` },
      { name: 'rocket_loader',         desc: 'Rocket Loader: async loading of third-party JavaScript to protect render-blocking resources.', path: (z)=>`zones/${z}/settings/rocket_loader` },
      { name: 'mirage',                desc: 'Mirage: lazy image loading and progressive enhancement for slow mobile connections.', path: (z)=>`zones/${z}/settings/mirage` },
      { name: 'early_hints',           desc: 'Early Hints: serves 103 responses with Link headers while the full response is still being prepared.', path: (z)=>`zones/${z}/settings/early_hints` },
      { name: 'prefetch_preload',      desc: 'Prefetch Preload: prefetches likely next-page resources (link href with Cloudflare hint headers).', path: (z)=>`zones/${z}/settings/prefetch_preload` },
      { name: 'response_buffering',    desc: 'Response Buffering: holds full responses at the edge before sending (vs streaming) to free origin resources.', path: (z)=>`zones/${z}/settings/response_buffering` },
      { name: 'mobile_redirect',       desc: 'Automatic Mobile Redirect: forwards mobile visitors to a mobile subdomain.', path: (z)=>`zones/${z}/settings/mobile_redirect` },
      { name: 'browser_cache_ttl',     desc: 'Browser Cache TTL: default Cache-Control max-age sent to browsers.', path: (z)=>`zones/${z}/settings/browser_cache_ttl` },
      { name: 'development_mode',      desc: 'Development Mode: temporarily bypasses cache (3h window) while making origin changes.', path: (z)=>`zones/${z}/settings/development_mode` },
      { name: 'speed_brain',           desc: 'Speed Brain: uses speculative loading hints to prerender likely navigations.', path: (z)=>`zones/${z}/speed_brain` },
      { name: 'fonts',                 desc: 'Fonts: auto-routes Google Fonts through Cloudflare for privacy and performance.', path: (z)=>`zones/${z}/settings/fonts` },
    ]
  },
  {
    label: 'DNS',
    key: 'dns',
    endpoints: [
      { name: 'dns_records', desc: 'DNS records: A/AAAA/CNAME/MX/TXT/etc. entries. Restored by matching type + name, pairing changed content to avoid delete/create downtime.', path: (z)=>`zones/${z}/dns_records?per_page=500` },
      { name: 'dnssec',      desc: 'DNSSEC status (active/disabled) with DS record details. View-only — toggling DNSSEC changes the delegation chain and needs registrar coordination.', path: (z)=>`zones/${z}/dnssec` },
    ]
  },
  {
    label: 'Cloudflare One (Zero Trust)',
    key: 'zero_trust',
    endpoints: [
      { name: 'zt_organization',       desc: 'Zero Trust organization: login page branding, auth domain (e.g. acme.cloudflareaccess.com), session durations and general Access settings.', path: (_,a)=>`accounts/${a}/access/organizations`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_apps',           desc: 'Access applications: self-hosted apps (domain + policy bindings) and SaaS apps, including inline session-duration policies.', path: (_,a)=>`accounts/${a}/access/apps?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_policies',       desc: 'Reusable Access policies: include/require/compose identity rules (emails, groups, IdPs, geos, device posture) attached to apps.', path: (_,a)=>`accounts/${a}/access/policies?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_groups',         desc: 'Access groups: named identity groups (include/require lists) reused across apps and policies.', path: (_,a)=>`accounts/${a}/access/groups?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_service_tokens', desc: 'Service tokens: machine-to-machine authentication for Access-protected origins (headers CF-Access-Client-Id/Secret).', path: (_,a)=>`accounts/${a}/access/service_tokens?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_ca_certs',       desc: 'Gateway CA certificates for authenticated origin pulls. View-only — private keys are never returned.', path: (_,a)=>`accounts/${a}/access/gateway_ca`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_idp',            desc: 'Identity providers: SAML, OIDC, Google, GitHub, Okta, AzureAD… log-in options for Zero Trust.', path: (_,a)=>`accounts/${a}/access/identity_providers?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'access_keys',           desc: 'Access key rotation: the interval setting (rotation state is runtime). View-only — key material cannot be rewritten via API.', path: (_,a)=>`accounts/${a}/access/keys`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'tunnels',               desc: 'Cloudflare Tunnel definitions: hostname routes through cloudflared connectors to origins without public ingress.', path: (_,a)=>`accounts/${a}/cfd_tunnel?is_deleted=false&per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'tunnel_routes',         desc: 'Tunnel IP routes: private network CIDRs reachable through named tunnels (WARP client → internal IPs).', path: (_,a)=>`accounts/${a}/teamnet/routes?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'tunnel_virtual_networks',desc: 'Tunnel virtual networks: segmentation of tunnel routes into named networks (e.g. prod vs corp).', path:(_,a)=>`accounts/${a}/teamnet/virtual_networks?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_settings',     desc: 'Gateway configuration: network policies master switch, HTTPS/body inspection, certificate usage.', path: (_,a)=>`accounts/${a}/gateway`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_dns_locations', desc: 'Gateway DNS resolver locations (DoH endpoints) devices can point at.', path: (_,a)=>`accounts/${a}/gateway/locations?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_lists',         desc: 'Gateway lists: reusable IP/domain/URL/serial lists referenced by Gateway policies — stored WITH their items.', path: (_,a)=>`accounts/${a}/gateway/lists?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_rules',         desc: 'Gateway policies: DNS (resolve/block), HTTP (web proxy filters) and Network (L4) rules protecting your users.', path: (_,a)=>`accounts/${a}/gateway/rules?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_certificates',  desc: 'Gateway edge certificates for HTTPS interception. View-only — private keys are never returned.', path: (_,a)=>`accounts/${a}/gateway/certificates`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'gateway_proxy_endpoints',desc: 'Gateway proxy endpoints: dedicated egress IPs for Gateway-protected traffic.', path:(_,a)=>`accounts/${a}/gateway/proxy_endpoints?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'device_posture_rules',  desc: 'Device posture rules: compliance checks (disk encryption, firewall, EDR, OS version) gating Access/WARP sessions.', path: (_,a)=>`accounts/${a}/devices/posture?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'device_posture_integrations',desc: 'Device posture integrations: third-party UEM/EDR providers (CrowdStrike, SentinelOne…) feeding posture results.', path:(_,a)=>`accounts/${a}/devices/posture/integrations`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'device_settings',       desc: 'Device enrollment: WARP client enrollment permissions and agent settings.', path: (_,a)=>`accounts/${a}/devices/settings`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'split_tunnel',          desc: 'Fallback domain list (split-tunnel DNS defaults): domains the WARP client resolves directly instead of through Gateway.', path: (_,a)=>`accounts/${a}/devices/policy/fallback_domains`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'dex_tests',             desc: 'Digital Experience Monitoring (DEX) test definitions: HTTP, traceroute and speed tests run from WARP devices. Config only — results/analytics are never fetched.', path: (_,a)=>`accounts/${a}/devices/dex_tests?per_page=100`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'risk_scoring_settings', desc: 'Zero Trust risk scoring: how session risk is computed from user, device and network signals.', path: (_,a)=>`accounts/${a}/zt_risk_scoring/settings`, accountRequired: true, scope: 'account', product: 'one' },
      { name: 'dlp_profiles',          desc: 'DLP profiles: detection entries (credit cards, PII patterns, keywords) used in Gateway/DLP rules. Match counters are runtime and ignored.', path: (_,a)=>`accounts/${a}/dlp/profiles`, accountRequired: true, scope: 'account', product: 'one' },
    ]
  },
  {
    label: 'Account WAF (Custom Rules, IP Access Rules)',
    key: 'account_sec',
    endpoints: [
      { name: 'waf_custom_rules_acct', desc: 'Account-level custom WAF ruleset: firewall custom rules that apply to ALL zones in the account.', path: (_,a)=>`accounts/${a}/rulesets?phase=http_request_firewall_custom`, accountRequired: true, scope: 'account' },
      { name: 'ip_access_rules_acct', desc: 'Account-level IP Access Rules: allow/challenge/block applied across every zone in the account.', path: (_,a)=>`accounts/${a}/firewall/access_rules/rules?per_page=100`, accountRequired: true, scope: 'account' },
    ]
  }
];

export function categoryLabel(key) {
  const c = CATEGORIES.find(c => c.key === key);
  return c ? c.label : key;
}

export function endpointScope(ep) {
  return ep.scope || 'zone';
}
