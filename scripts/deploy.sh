#!/bin/sh
# Deploy helper — picks the right Wrangler config:
#   wrangler.local.toml (git-ignored, real account/database ids) if present,
#   otherwise the committed wrangler.toml (Deploy-to-Cloudflare flow, where
#   Cloudflare provisions D1/R2 and rewrites the ids in the cloned repo).
# Migrations are applied by binding name (DB) so the command works regardless
# of what the generated database is named.
set -e
if [ -f wrangler.local.toml ]; then
  CFG=wrangler.local.toml
else
  CFG=wrangler.toml
fi
echo "── using config: $CFG"
npx wrangler d1 migrations apply --config "$CFG" DB --remote
npx wrangler deploy --config "$CFG"
