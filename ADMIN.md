# HACKSTROM — Security & Admin

## Admin access
The dashboard is protected **on the server** — the admin HTML is never sent to
unauthenticated visitors (they get a `401` login page instead).

| Host | Protected by |
|---|---|
| **https://hackstrom.pages.dev/admin** | Pages Advanced Mode (`_worker.js`) |
| https://hackstrom.fahemrayane.workers.dev/admin | Cloudflare Worker (`src/worker.js`) |

Both behave the same:
- wrong password → `401`
- correct password → `303` + signed `HttpOnly; Secure; SameSite=Strict` cookie (8 h)
- `/admin.html` → `308` redirect to `/admin`
- `/admin/logout` → clears the session
- responses are `Cache-Control: no-store`, `X-Robots-Tag: noindex`

## How it works
The same logic (`src/worker.js`) runs in two places:
1. **Worker** — `wrangler.toml` → `main = "src/worker.js"`, assets binding `ASSETS`.
2. **Pages** — `scripts/deploy-pages.sh` copies it to `_worker.js` in the upload dir.

Required secrets (set once, per platform):

| Secret | Meaning |
|---|---|
| `ADMIN_PASSWORD_HASH` | hex SHA‑256 of the admin password |
| `SESSION_SECRET`      | random key used to sign session cookies |

```bash
# Worker
printf '%s' "$HASH" | npx wrangler secret put ADMIN_PASSWORD_HASH
printf '%s' "$KEY"  | npx wrangler secret put SESSION_SECRET

# Pages
printf '%s' "$HASH" | npx wrangler pages secret put ADMIN_PASSWORD_HASH --project-name hackstrom
printf '%s' "$KEY"  | npx wrangler pages secret put SESSION_SECRET --project-name hackstrom
```

## Deploy
```bash
bash scripts/deploy-pages.sh          # public site + protected admin (Pages)
npx wrangler deploy                   # Worker  (also auto-deploys from Git on push)
```

## Rotate the admin password
```bash
# 1) server-side hash (do it for BOTH worker and pages, see above)
printf '%s' 'NEW_PASSWORD' | sha256sum | cut -d' ' -f1

# 2) client-side fallback in src/js/admin.js → PASS_SALT / PASS_KEY
python3 -c "import os,hashlib; s=os.urandom(16).hex(); \
  print('PASS_SALT =', repr(s)); \
  print('PASS_KEY  =', repr(hashlib.pbkdf2_hmac('sha256', b'NEW_PASSWORD', s.encode(), 200000, 32).hex()))"
```

## Rotate the session-signing key
```bash
openssl rand -hex 32
```

## Hardening applied
- Strict CSP — `script-src 'self'` (no `'unsafe-inline'`), `object-src 'none'`.
- All inline scripts extracted (`src/js/loader.js`, `src/js/admin.js`).
- XSS-safe rendering (`esc` / `escAttr`, numeric coercion).
- SRI on the jsDelivr icon stylesheet.
- Headers: HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, `COOP`, `CORP`, `X-Permitted-Cross-Domain-Policies: none`.
- `robots.txt` disallows `/admin`.
- `.assetsignore` keeps `.git`, `.wrangler`, `wrangler.toml`, `src/worker.js`
  out of the served assets.

## GitHub token
Use a **Fine-grained** token limited to repository `rayaner45/hackstrom`
with **Contents: Read and write** only. Never commit a token or the password.
