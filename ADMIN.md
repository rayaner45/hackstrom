# HACKSTROM — Security & Admin

## Admin access
The dashboard is protected **on the server** — the admin HTML is never sent to
unauthenticated visitors (they get a `401` login page instead).

| Host | Protected by |
|---|---|
| **https://hackstrom.pages.dev/admin** | Pages Advanced Mode (`_worker.js`) |
| https://hackstrom.fahemrayane.workers.dev/admin | Cloudflare Worker |

Login flow: password → `303` + signed session cookie →
`__Host-hs_admin` (`HttpOnly; Secure; SameSite=Strict; Max-Age=28800`).
Logout: `/admin/logout`. No session ⇒ always `401` + `Cache-Control: no-store`.

## How it works
The same `src/worker.js` runs in both places:

```bash
bash scripts/deploy-pages.sh   # public site + protected admin (Pages, via _worker.js)
npx wrangler deploy            # Worker (also auto-deploys from Git on push)
```

Required secrets (set once, for **both** the Worker and the Pages project):

| Secret | Meaning |
|---|---|
| `ADMIN_PASSWORD_HASH` | hex SHA‑256 of the admin password |
| `SESSION_SECRET`      | random key used to sign session cookies |

```bash
printf '%s' "$HASH" | npx wrangler secret put ADMIN_PASSWORD_HASH
printf '%s' "$KEY"  | npx wrangler secret put SESSION_SECRET
printf '%s' "$HASH" | npx wrangler pages secret put ADMIN_PASSWORD_HASH --project-name hackstrom
printf '%s' "$KEY"  | npx wrangler pages secret put SESSION_SECRET      --project-name hackstrom
```

## Hardening applied

### Authentication / session
- Password verified on Cloudflare (SHA‑256, constant-time comparison).
- Session = HMAC‑SHA256 signed token; **`__Host-` cookie prefix** (binds the
  cookie to the exact host, blocks subdomain cookie injection).
- `HttpOnly`, `Secure`, `SameSite=Strict`, 8‑hour expiry, 30‑byte random key.
- Login served only when `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` are set.

### Brute-force protection
- Server-side throttle: ≥ `5` failed logins per IP in `15 min` ⇒ `429` +
  `Retry-After` (state kept in the edge cache so it is shared across isolates,
  with a per-isolate mirror for tightness).
- Randomised delay on every failure.

### Request hardening
- `400` on path traversal / null bytes / malformed encoding.
- `405` on any method that is not `GET`/`HEAD` (`POST` only for `/admin`).
- Internal paths are always `404` (worker source, `_worker.js`, `_headers`,
  `_redirects`, `wrangler.toml`, `scripts/`, `.git/`, and any `*.md` / `*.toml`
  / `*.sh` / `*.lock` / `*.yml`).
- Unknown paths return a **real `404`** (styled `404.html`,
  `not_found_handling = "404-page"`) — never the SPA fallback / homepage.

### Content / transport
- Strict CSP: `script-src 'self'`, `script-src-attr 'none'`,
  `object-src 'none'`, no `'unsafe-inline'` for scripts, image sources limited
  to self / `data:` / Discord‑GitHub CDNs.
- All inline scripts extracted to `src/js/*.js`; XSS-safe rendering (`esc`/`escAttr`).
- SRI on the jsDelivr icon stylesheet.
- HSTS (preload), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, COOP, CORP, `X-Permitted-Cross-Domain-Policies: none`.
- `robots.txt` disallows `/admin`.

### Publishing
- `.assetsignore` is a **deny-all allow-list**: only the real public files
  (`index.html`, `admin.html`, `404.html`, `robots.txt`, `_headers`,
  `src/css/main.css`, `src/js/*.js`, `data/leaderboard.json`) are published.
  Internal files are invisible to the public.

## Rotate the admin password
```bash
# 1) server-side hash — update BOTH worker and pages secrets
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

## GitHub token
Use a **Fine-grained** token limited to repository `rayaner45/hackstrom` with
**Contents: Read and write** only. Never commit a token or the password.
