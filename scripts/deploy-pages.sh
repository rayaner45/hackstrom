#!/usr/bin/env bash
# Deploy the HACKSTROM site to Cloudflare Pages (project: "hackstrom").
#
# The admin dashboard is protected on the server by `_worker.js`
# (Cloudflare Pages Advanced Mode) — it is never served to unauthenticated
# visitors. Required Pages secrets (set once):
#   npx wrangler pages secret put ADMIN_PASSWORD_HASH --project-name hackstrom
#   npx wrangler pages secret put SESSION_SECRET      --project-name hackstrom
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="/tmp/hs-public"
rm -rf "$OUT"
mkdir -p "$OUT/src/css" "$OUT/src/js" "$OUT/data"

cp index.html admin.html 404.html robots.txt _headers "$OUT/"
cp src/css/main.css "$OUT/src/css/"
cp src/js/main.js src/js/loader.js src/js/admin.js "$OUT/src/js/"
cp data/leaderboard.json "$OUT/data/"

# The same Worker logic protects the admin on Pages (Advanced Mode).
cp src/worker.js "$OUT/_worker.js"

echo "→ Deploying $OUT to Pages project 'hackstrom'"
npx --yes wrangler@4.151.1 pages deploy "$OUT" \
  --project-name hackstrom --branch main --commit-dirty=true
